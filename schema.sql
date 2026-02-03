-- =========================
-- USERS
-- =========================
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'voter',
  verified INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- =========================
-- ELECTIONS
-- =========================
CREATE TABLE IF NOT EXISTS elections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT,
  election_type TEXT NOT NULL DEFAULT 'public',
  status TEXT DEFAULT 'ongoing',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- =========================
-- CANDIDATES
-- =========================
CREATE TABLE IF NOT EXISTS candidates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  election_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  department TEXT,
  year TEXT,
  manifesto TEXT,
  photo_url TEXT,
  votes INTEGER DEFAULT 0,
  FOREIGN KEY(election_id) REFERENCES elections(id) ON DELETE CASCADE
);

-- =========================
-- VOTES
-- =========================
CREATE TABLE IF NOT EXISTS votes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  election_id INTEGER NOT NULL,
  candidate_id INTEGER NOT NULL,
  voted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(election_id) REFERENCES elections(id) ON DELETE CASCADE,
  FOREIGN KEY(candidate_id) REFERENCES candidates(id) ON DELETE CASCADE,
  UNIQUE(user_id, election_id)
);

-- =========================
-- OTPS
-- =========================
CREATE TABLE IF NOT EXISTS otps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  election_id INTEGER NOT NULL,
  otp_code TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  used INTEGER DEFAULT 0,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(election_id) REFERENCES elections(id) ON DELETE CASCADE
);

-- =========================
-- VOTER LIST
-- =========================
CREATE TABLE IF NOT EXISTS voter_list (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  roll_no TEXT,
  allowed INTEGER DEFAULT 1
);