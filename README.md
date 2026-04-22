# SecureNotes — Flask Web Application Security Project

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.x-black?logo=flask)
![SQLite](https://img.shields.io/badge/Database-SQLite-003B57?logo=sqlite)


---

## 1. Project Title and Overview

**SecureNotes** is a Flask-based web application designed to demonstrate and address common real-world web security vulnerabilities. The application is a note-taking platform where users can register, log in, and manage personal notes, while an admin panel provides privileged access to all users and notes across the system.


<img width="1252" height="556" alt="image" src="https://github.com/user-attachments/assets/fcf1aed0-9d5c-4efe-9479-0054b146856e" />

The project is delivered in **two parallel versions**:

| Version | File | Description |
|---|---|---|
| Vulnerable | `main/app.py` | All security protections intentionally disabled |
| Secure | `Secure-code/app.py` | All vulnerabilities identified and fully fixed |

The primary purpose of this project is educational — to show exactly what insecure code looks like in a real application, and how each vulnerability is addressed in the secure version. The main security focus areas are SQL Injection prevention, authentication hardening, session security, XSS prevention, access control enforcement, and CSRF protection.

---

## 2. Features and Security Objectives

### Application Features

| Feature | Description |
|---|---|
| User Registration | New users can create an account with a username and password |
| User Login / Logout | Authenticated session management for all users |
| Create Notes | Logged-in users can write and save personal notes |
| Edit Notes | Users can update the content of their own notes |
| Delete Notes | Users can permanently remove their own notes |
| Admin Panel | Admin users can view all registered users and all notes in the system |
| Role-Based Access | Regular users and admin users have different levels of access |

### Security Objectives

The following security improvements were implemented in the secure version:

- **SQL Injection Prevention** — Parameterised queries replace all raw f-string SQL statements
- **Secure Password Storage** — Passwords are hashed using Werkzeug's `pbkdf2-sha256` algorithm before being stored
- **XSS Prevention** — Jinja2 auto-escaping is enforced across all templates; the `| safe` filter is removed
- **IDOR Prevention** — Ownership verification is enforced before any note can be read, edited, or deleted
- **CSRF Protection** — Flask-WTF CSRF tokens are required on all state-changing forms
- **Secure Session Handling** — Session cookies are configured with `HttpOnly`, `Secure`, and `SameSite` flags
- **Strong Secret Key** — Cryptographically random secret key replaces the hardcoded weak value
- **Security Response Headers** — `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, and other protective headers are applied to every response

---

## 3. Project Structure

```
securenotes/
│
├── main/                  # Vulnerable version of the application
│   ├── app.py                        # Flask app — all security protections off
│   ├── schema.sql                    # Database schema with plain-text passwords
│   └── templates/
│       ├── base.html                 # Shared layout (Bootstrap 5 navbar)
│       ├── login.html                # Login form (no CSRF token)
│       ├── register.html             # Registration form (no CSRF token)
│       ├── dashboard.html            # Notes list — renders content with | safe (XSS)
│       ├── edit_note.html            # Edit note form (no ownership check)
│       └── admin.html                # Admin panel (no CSRF on delete)
│
├── secure-code/                       # Secure version of the application
│   ├── app.py                        # Flask app — all vulnerabilities fixed
│   ├── schema.sql                    # Database schema with hashed passwords
│   └── templates/
│       ├── base.html                 # Shared layout (Bootstrap 5 navbar)
│       ├── login.html                # Login form with CSRF token
│       ├── register.html             # Registration form with CSRF token
│       ├── dashboard.html            # Notes list — auto-escaped content, POST delete
│       ├── edit_note.html            # Edit note form with CSRF token
│       └── admin.html                # Admin panel with CSRF-protected delete
│
└── README.md                         # Project documentation
```

### Key Files Explained

| File | Purpose |
|---|---|
| `main/app.py` | Intentionally vulnerable Flask app — used to demonstrate attacks |
| `secure-code/app.py` | Hardened Flask app — all 8 vulnerabilities resolved |
| `schema.sql` (vulnerable) | Creates tables and inserts users with plain-text passwords |
| `schema.sql` (secure) | Creates tables and inserts users with properly hashed passwords |
| `templates/base.html` | Master layout shared by all pages — navbar and flash messages |
| `templates/dashboard.html` | Main user page — note list, create form, edit/delete actions |
| `templates/admin.html` | Admin-only page — full user list and all notes |

---

## 4. Setup and Installation Instructions

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)
- Git

### Step 1 — Clone the Repository

```bash
git clone https://github.com/your-username/securenotes.git
cd securenotes
```

### Step 2 — Create a Virtual Environment (Recommended)

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Mac / Linux
source venv/bin/activate
```


### Step 3 — Run the Vulnerable Version

```bash
cd securenote_vuln
python app.py
```

### Step 4 — Run the Secure Version

```bash
cd securenote
python app.py
```

Visit `http://127.0.0.1:5000` in your browser.

> **Note:** The database (`securenotes.db`) is created automatically on first run from `schema.sql`. If you switch between the vulnerable and secure versions, delete `securenotes.db` before starting the other version to ensure the correct password format is used.

### Default Credentials

| Username | Password | Role  |
|----------|----------|-------|
| `admin`  | `admin123` | Admin |
| `alice`  | `alice123` | User  |
| `bob`    | `bob123`   | User  |

---

## 5. Usage Guidelines

### Registering an Account

1. Navigate to `http://127.0.0.1:5000`
2. Click **Register new account**
3. Enter a username and password (minimum 8 characters enforced in the secure version)
4. Click **Register** — you will be redirected to the login page

### Logging In

1. Enter your username and password on the login page
2. Click **Login** — you will be redirected to your personal dashboard
3. The navbar displays your username and role badge

### Managing Notes

- **Create** — Type a note in the input field on the dashboard and click **Add Note**
- **Edit** — Click the **Edit** button next to any note, update the content, and click **Save Changes**
- **Delete** — Click the **Delete** button next to any note and confirm the prompt

> In the **vulnerable version**, any logged-in user can edit or delete any note by changing the ID in the URL (e.g. `/note/edit/1`). In the **secure version**, this is blocked — users can only access their own notes and receive a `403 Forbidden` otherwise.

### Admin Panel

1. Log in with the `admin` account
2. Click **Admin Panel** in the navbar
3. The **Users** tab shows all registered accounts and their note counts
4. The **Notes** tab shows all notes across all users with delete options

### Demonstrating Vulnerabilities (Vulnerable Version Only)

| Attack | How to Test |
|---|---|
| SQL Injection | Enter `' OR '1'='1` as the username with any password on the login page |
| Stored XSS | Create a note containing `<script>alert('XSS')</script>` and reload the dashboard |
| IDOR | Log in as `alice`, then visit `/note/edit/1` to edit `admin`'s note |
| CSRF | Visit `/note/delete/1` directly in the browser address bar |

---

## 6. Security Improvements

### Vulnerability vs Secure — Side by Side

| # | Vulnerability | Vulnerable `app.py` | Secure `app.py` |
|---|---|---|---|
| 1 | SQL Injection | Raw f-string queries |  Parameterised `?` placeholders |
| 2 | Password Storage |  Plain text |  Hashed (pbkdf2-sha256) |
| 3 | XSS |  `\| safe` disables escaping |  Jinja2 auto-escaping |
| 4 | IDOR |  No ownership check |  `user_id` verified before access |
| 5 | CSRF |  No token, DELETE via GET |  Flask-WTF tokens, POST only |
| 6 | Secret Key |  `'supersecret'` hardcoded |  `secrets.token_hex(32)` |
| 7 | Session Cookies |  No flags set |  HttpOnly + Secure + SameSite |
| 8 | Security Headers |  None |  CSP, X-Frame-Options, and more |

---

### Fix 1 — SQL Injection → Parameterised Queries

```python
#  Vulnerable
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

#  Secure
cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
```
User input is treated strictly as data — never as SQL syntax. Payloads like `' OR '1'='1` or `'; DROP TABLE users; --` have no effect.

---

### Fix 2 — Plain-Text Passwords → Password Hashing

```python
#  Vulnerable — stored as-is
db.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')")

#  Secure — hashed before storage, verified on login
hashed = generate_password_hash(password)
db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed, role))

if user and check_password_hash(user['password'], password):
    ...
```

---

### Fix 3 — XSS → Jinja2 Auto-Escaping

```html
<!--  Vulnerable — executes injected scripts -->
{{ note.content | safe }}

<!--  Secure — converts <script> to visible text -->
{{ note.content }}
```

---

### Fix 4 — IDOR → Ownership Check

```python
#  Secure — added after fetching the note in edit and delete routes
if note['user_id'] != session['user_id'] and session.get('role') != 'admin':
    abort(403)
```

---

### Fix 5 — CSRF → Flask-WTF Token

```python
#  Secure — enabled globally in app.py
csrf = CSRFProtect(app)
```

```html
<!--  Added to every POST form in all templates -->
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
```

The delete action was also changed from a `GET` link to a `POST` form — a plain URL visit can no longer trigger deletion.

---

### Fix 6 — Hardcoded Secret Key → Random Key

```python
#  Vulnerable
app.secret_key = 'supersecret'

#  Secure
app.secret_key = secrets.token_hex(32)
```

---

### Fix 7 — Insecure Cookies → Secure Cookie Flags

```python
#  Secure
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # JS cannot read the cookie
    SESSION_COOKIE_SECURE=True,     # HTTPS only
    SESSION_COOKIE_SAMESITE='Lax',  # Blocks cross-origin attachment
)
```

---

### Fix 8 — Missing Headers → Security Response Headers

```python
#  Secure — applied to every response via after_request hook
response.headers['Content-Security-Policy'] = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net; "
    "style-src 'self' https://cdn.jsdelivr.net;"
)
response.headers['X-Frame-Options']        = 'DENY'
response.headers['X-Content-Type-Options'] = 'nosniff'
response.headers['Referrer-Policy']        = 'strict-origin-when-cross-origin'
response.headers['Permissions-Policy']     = 'geolocation=(), microphone=(), camera=()'
```

---

## 7. Testing Process

### Testing Approach

Both versions of the application were tested using **manual black-box testing** and **browser-based attack simulation** to validate the presence of vulnerabilities in the vulnerable version and confirm their resolution in the secure version.

---

### Tools Used

| Tool | Purpose |
|---|---|
| **Browser DevTools** (Firefox / Chrome) | Inspecting cookies, headers, network requests, and console output |
| **Browser Address Bar** | Manually crafting URLs to test IDOR and CSRF via GET |
| **Application Forms** | Submitting attack payloads directly through the UI |
| **SQLite Browser** | Inspecting the raw database to verify password storage format |
| **Python `werkzeug`** | Verifying `check_password_hash` behaviour against stored values |

---

### Test Cases and Findings

#### SQL Injection

| Test Input | Vulnerable Result | Secure Result |
|---|---|---|
| Username: `' OR '1'='1`, Password: *(blank)* |  Login bypassed — logged in as admin |  Rejected — Invalid credentials |
| Username: `'; DROP TABLE users; --` |  Users table destroyed |  Input treated as data, no effect |

#### XSS — Cross-Site Scripting

| Test Input | Vulnerable Result | Secure Result |
|---|---|---|
| Note: `<script>alert('XSS')</script>` |  Alert executes on dashboard load |  Displayed as plain text |
| Note: `<img src=x onerror=alert(1)>` |  Alert executes |  Rendered as escaped text |

#### IDOR — Insecure Direct Object Reference

| Test | Vulnerable Result | Secure Result |
|---|---|---|
| Logged in as `alice`, visit `/note/edit/1` |  Admin's note loads and is editable |  403 Forbidden |
| Visit `/note/delete/1` as any logged-in user |  Note deleted without ownership check |  403 Forbidden |

#### CSRF — Cross-Site Request Forgery

| Test | Vulnerable Result | Secure Result |
|---|---|---|
| Visit `/note/delete/1` directly in browser |  Note deleted via GET request |  Method Not Allowed — POST required |
| POST form submitted without `csrf_token` |  Request accepted |  400 Bad Request — token missing |

#### Password Storage

| Test | Vulnerable Result | Secure Result |
|---|---|---|
| Inspect `securenotes.db` users table |  Passwords visible as plain text (`admin123`) |  Stored as `pbkdf2:sha256:...` hash |

#### Session Cookies

| Test | Vulnerable Result | Secure Result |
|---|---|---|
| Inspect session cookie in DevTools |  No `HttpOnly`, `Secure`, or `SameSite` flags |  All three flags present |

#### Security Headers

| Test | Vulnerable Result | Secure Result |
|---|---|---|
| Inspect response headers in DevTools Network tab |  No CSP, no X-Frame-Options |  All headers present and correctly configured |

---

### Key Findings Summary

- All **8 vulnerabilities** were successfully demonstrated in the vulnerable version
- All **8 vulnerabilities** were confirmed resolved in the secure version
- **SQL Injection on the login form** was the highest-risk vulnerability — it granted full admin access with no password
- **Plain-text password storage** meant any database breach would instantly expose all user credentials
- The **CSRF + GET delete** combination meant any `<img>` tag or link could silently delete user data without any interaction

---

## 8. Contributions and References

### Frameworks and Libraries

| Resource | Purpose | Link |
|---|---|---|
| Flask | Python web framework | https://flask.palletsprojects.com |
| Werkzeug | Password hashing utilities | https://werkzeug.palletsprojects.com |
| Flask-WTF | CSRF protection for Flask forms | https://flask-wtf.readthedocs.io |
| Bootstrap 5 | Frontend UI components and layout | https://getbootstrap.com |
| Jinja2 | HTML templating engine with auto-escaping | https://jinja.palletsprojects.com |
| SQLite3 | Lightweight embedded database | https://www.sqlite.org |

### Security References

| Resource | Link |
|---|---|
| OWASP Top 10 Web Application Security Risks | https://owasp.org/www-project-top-ten |
| OWASP SQL Injection Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html |
| OWASP XSS Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html |
| OWASP CSRF Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html |
| OWASP Session Management Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html |
| Flask Security Considerations (Official Docs) | https://flask.palletsprojects.com/en/latest/security |
| MDN Web Docs — Content Security Policy | https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP |

---

