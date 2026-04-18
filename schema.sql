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

-- Passwords are hashed with Werkzeug scrypt (secure app compatible)
-- Plain-text equivalents: admin=admin123, alice=alice123, bob=bob123
INSERT INTO users (username, password, role) VALUES
    ('admin', 'scrypt:32768:8:1$g7SDQAZMxKIL6rwL$215da566643d77fa3bacb9f08eecfc19f24f22cd5dcdbb3ef32edee6643be8fc5577a79e84074d72e4a82134ddfe2ca003cdbb7c5d7da49650ddd5ae189d1d64', 'admin'),
    ('alice', 'scrypt:32768:8:1$XwypQOvkq5kOhY0R$5f209ccc569f10d5a4cd6aed24663855adff6c53052bbf362fd2405489f9abdc41d2aea017319759f1720e35a6f6329ede7f1419cc166f84db003c44f19a43f9', 'user'),
    ('bob',   'scrypt:32768:8:1$j33Sub4f2JLT9pX2$f7069f22b6bf1442f74253c54e4dd11b58e5e21f5fc4f412fa7d1deee76220d3a15b674c3687f95646f8ce5385d4b242ee1ce31061ca3049bf78251d278757f4',   'user');

INSERT INTO notes (user_id, content) VALUES
    (2, 'Alice first note: Buy groceries'),
    (2, 'Alice second note: Call dentist'),
    (3, 'Bob note: Prepare presentation');
