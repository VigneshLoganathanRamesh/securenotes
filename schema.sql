DROP TABLE IF EXISTS notes;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('user', 'admin')) DEFAULT 'user'
);

CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Insert sample data for testing
INSERT INTO users (username, password, role) VALUES 
    ('admin', 'admin123', 'admin'),
    ('alice', 'alice123', 'user'),
    ('bob', 'bob123', 'user');

INSERT INTO notes (user_id, content) VALUES
    (2, 'Alice first note: Buy groceries'),
    (2, 'Alice second note: Call dentist'),
    (3, 'Bob note: Prepare presentation');