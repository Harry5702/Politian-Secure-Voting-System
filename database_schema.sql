-- Database Schema for Politian (Secure Voting System)
-- This file contains all the database queries used in the project

-- Table Definitions
CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    cnic VARCHAR(15) UNIQUE NOT NULL,
    password VARCHAR(120) NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    login_attempts INTEGER DEFAULT 0,
    account_locked BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS candidate (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    party VARCHAR(100) NOT NULL,
    image VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    vote_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS vote (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    candidate_id INTEGER NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    device_info VARCHAR(200),
    FOREIGN KEY (user_id) REFERENCES user(id),
    FOREIGN KEY (candidate_id) REFERENCES candidate(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action VARCHAR(50) NOT NULL,
    details TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    FOREIGN KEY (user_id) REFERENCES user(id)
);

-- Indexes for Better Performance
CREATE INDEX IF NOT EXISTS idx_user_email_username ON user(email, username);
CREATE INDEX IF NOT EXISTS idx_vote_timestamp ON vote(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_candidate_party ON candidate(party);

-- Views for Analytics
CREATE VIEW IF NOT EXISTS detailed_voting_stats AS
WITH vote_counts AS (
    SELECT COUNT(*) as total_votes FROM vote
)
SELECT 
    c.name,
    c.party,
    COUNT(v.id) as vote_count,
    CASE 
        WHEN (SELECT total_votes FROM vote_counts) > 0 
        THEN (COUNT(v.id) * 100.0 / (SELECT total_votes FROM vote_counts))
        ELSE 0 
    END as percentage
FROM candidate c
LEFT JOIN vote v ON c.id = v.candidate_id
GROUP BY c.id, c.name, c.party
ORDER BY vote_count DESC;

CREATE VIEW IF NOT EXISTS user_activity AS
SELECT 
    u.username,
    u.email,
    COUNT(v.id) as vote_count,
    CASE 
        WHEN MAX(v.timestamp) IS NOT NULL 
        THEN datetime(MAX(v.timestamp), '+5 hours') 
        ELSE NULL 
    END as last_vote,
    CASE 
        WHEN u.last_login IS NOT NULL 
        THEN datetime(u.last_login, '+5 hours') 
        ELSE NULL 
    END as last_login
FROM user u
LEFT JOIN vote v ON u.id = v.user_id
GROUP BY u.id, u.username, u.email, u.last_login;

CREATE VIEW IF NOT EXISTS hourly_vote_distribution AS
SELECT 
    strftime('%H', timestamp) as hour,
    COUNT(*) as vote_count
FROM vote
WHERE timestamp >= datetime('now', '-7 days')
GROUP BY strftime('%H', timestamp)
ORDER BY hour;

CREATE VIEW IF NOT EXISTS voter_demographics AS
SELECT 
    c.party,
    COUNT(DISTINCT v.user_id) as unique_voters,
    COUNT(v.id) as total_votes,
    MAX(v.timestamp) as last_vote_time
FROM candidate c
LEFT JOIN vote v ON c.id = v.candidate_id
GROUP BY c.party;

-- Common Queries Used in the Application

-- Get Voting Statistics
SELECT 
    c.name,
    c.party,
    COUNT(v.id) as vote_count,
    CASE 
        WHEN (SELECT COUNT(*) FROM vote) > 0 
        THEN (COUNT(v.id) * 100.0 / (SELECT COUNT(*) FROM vote))
        ELSE 0 
    END as percentage
FROM candidate c
LEFT JOIN vote v ON c.id = v.candidate_id
GROUP BY c.id, c.name, c.party
ORDER BY vote_count DESC;

-- Get User Activity
SELECT 
    u.username,
    u.email,
    COUNT(v.id) as vote_count,
    datetime(MAX(v.timestamp), '+5 hours') as last_vote,
    datetime(u.last_login, '+5 hours') as last_login
FROM user u
LEFT JOIN vote v ON u.id = v.user_id
GROUP BY u.id, u.username, u.email, u.last_login
ORDER BY last_vote DESC NULLS LAST;

-- Get Audit Logs
SELECT 
    al.id,
    al.action,
    al.details,
    datetime(al.timestamp, '+5 hours') as timestamp,
    al.ip_address,
    u.username
FROM audit_log al
LEFT JOIN user u ON al.user_id = u.id
ORDER BY al.timestamp DESC
LIMIT 100;

-- Get Vote Trends (Last 30 Days)
SELECT 
    date(timestamp) as vote_date,
    COUNT(*) as vote_count
FROM vote
WHERE timestamp >= date('now', '-30 days')
GROUP BY date(timestamp)
ORDER BY vote_date;

-- Get Overview Statistics
SELECT 
    (SELECT COUNT(*) FROM vote) as total_votes,
    (SELECT COUNT(*) FROM user WHERE last_login >= datetime('now', '-7 days')) as active_users,
    (SELECT COUNT(*) FROM candidate) as total_candidates,
    (SELECT COUNT(*) FROM audit_log WHERE action IN ('SECURITY', 'LOGIN_FAILED')) as security_events;

-- Get Detailed Analytics
SELECT 
    c.name as candidate_name,
    c.party,
    COUNT(v.id) as total_votes,
    COUNT(DISTINCT v.user_id) as unique_voters,
    MAX(v.timestamp) as last_vote,
    (
        SELECT COUNT(*)
        FROM vote v2
        WHERE v2.candidate_id = c.id
        AND v2.timestamp >= datetime('now', '-1 hour')
    ) as votes_last_hour
FROM candidate c
LEFT JOIN vote v ON c.id = v.candidate_id
GROUP BY c.id, c.name, c.party
ORDER BY total_votes DESC;

-- Get Daily Audit Statistics
WITH daily_stats AS (
    SELECT 
        date(timestamp) as audit_date,
        action,
        COUNT(*) as action_count,
        COUNT(DISTINCT user_id) as unique_users
    FROM audit_log
    WHERE timestamp >= date('now', '-30 days')
    GROUP BY date(timestamp), action
)
SELECT 
    audit_date,
    json_group_object(action, action_count) as action_counts,
    SUM(unique_users) as total_unique_users
FROM daily_stats
GROUP BY audit_date
ORDER BY audit_date DESC;

-- Triggers
CREATE TRIGGER IF NOT EXISTS after_vote_insert
AFTER INSERT ON vote
BEGIN
    UPDATE candidate 
    SET vote_count = vote_count + 1 
    WHERE id = NEW.candidate_id;
    
    INSERT INTO audit_log (user_id, action, details, timestamp, ip_address)
    VALUES (
        NEW.user_id,
        'VOTE',
        'Vote cast for candidate ID ' || NEW.candidate_id,
        CURRENT_TIMESTAMP,
        NEW.ip_address
    );
END;

CREATE TRIGGER IF NOT EXISTS after_failed_login
AFTER UPDATE ON user
WHEN NEW.login_attempts >= 3 AND OLD.login_attempts < 3
BEGIN
    UPDATE user SET account_locked = 1 WHERE id = NEW.id;
    
    INSERT INTO audit_log (user_id, action, details, timestamp)
    VALUES (
        NEW.id,
        'SECURITY',
        'Account locked due to multiple failed login attempts',
        CURRENT_TIMESTAMP
    );
END; 