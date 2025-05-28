from app import app, db
from sqlalchemy import event, text, DDL
from datetime import datetime

# Advanced Triggers
def create_triggers():
    with app.app_context():
        # Trigger for vote audit logging with detailed information
        db.session.execute(text("""
            CREATE TRIGGER IF NOT EXISTS vote_audit_trigger
            AFTER INSERT ON vote
            BEGIN
                INSERT INTO audit_log (user_id, action, details, timestamp, ip_address)
                SELECT 
                    NEW.user_id,
                    'VOTE_CAST',
                    json_object(
                        'candidate_id', NEW.candidate_id,
                        'candidate_name', (SELECT name FROM candidate WHERE id = NEW.candidate_id),
                        'party', (SELECT party FROM candidate WHERE id = NEW.candidate_id),
                        'timestamp', datetime('now')
                    ),
                    datetime('now'),
                    NEW.ip_address;
            END;
        """))

        # Trigger for user activity tracking
        db.session.execute(text("""
            CREATE TRIGGER IF NOT EXISTS user_activity_trigger
            AFTER UPDATE ON user
            WHEN OLD.last_login != NEW.last_login
            BEGIN
                INSERT INTO audit_log (user_id, action, details, timestamp)
                VALUES (
                    NEW.id,
                    'USER_ACTIVITY',
                    json_object(
                        'type', 'login',
                        'previous_login', OLD.last_login,
                        'current_login', NEW.last_login
                    ),
                    datetime('now')
                );
            END;
        """))

        # Trigger for vote count maintenance
        db.session.execute(text("""
            CREATE TRIGGER IF NOT EXISTS update_vote_count_trigger
            AFTER INSERT ON vote
            BEGIN
                UPDATE candidate
                SET vote_count = (
                    SELECT COUNT(*)
                    FROM vote
                    WHERE candidate_id = NEW.candidate_id
                )
                WHERE id = NEW.candidate_id;
            END;
        """))

# Complex Views
def create_views():
    with app.app_context():
        # View for detailed voting statistics
        db.session.execute(text("""
            CREATE VIEW IF NOT EXISTS detailed_voting_stats AS
            SELECT 
                c.id as candidate_id,
                c.name as candidate_name,
                c.party,
                COUNT(v.id) as total_votes,
                COUNT(DISTINCT v.user_id) as unique_voters,
                ROUND(COUNT(v.id) * 100.0 / (SELECT COUNT(*) FROM vote), 2) as vote_percentage,
                MAX(v.timestamp) as last_vote_time,
                (
                    SELECT COUNT(*)
                    FROM vote v2
                    WHERE v2.candidate_id = c.id
                    AND v2.timestamp >= datetime('now', '-24 hours')
                ) as votes_last_24h
            FROM candidate c
            LEFT JOIN vote v ON c.id = v.candidate_id
            GROUP BY c.id, c.name, c.party;
        """))

        # View for user voting patterns
        db.session.execute(text("""
            CREATE VIEW IF NOT EXISTS user_voting_patterns AS
            SELECT 
                u.id as user_id,
                u.username,
                v.timestamp as vote_time,
                c.name as voted_for,
                c.party as voted_party,
                CASE 
                    WHEN v.timestamp >= datetime('now', '-1 hour') THEN 'Last Hour'
                    WHEN v.timestamp >= datetime('now', '-24 hours') THEN 'Last 24 Hours'
                    WHEN v.timestamp >= datetime('now', '-7 days') THEN 'Last Week'
                    ELSE 'Older'
                END as vote_period
            FROM user u
            LEFT JOIN vote v ON u.id = v.user_id
            LEFT JOIN candidate c ON v.candidate_id = c.id;
        """))

# Stored Procedures (Using SQLite's CREATE PROCEDURE alternative)
def create_stored_procedures():
    with app.app_context():
        # Procedure for getting hourly vote distribution
        db.session.execute(text("""
            CREATE VIEW IF NOT EXISTS hourly_vote_distribution AS
            WITH RECURSIVE hours(hour) AS (
                SELECT 0
                UNION ALL
                SELECT hour + 1 FROM hours WHERE hour < 23
            )
            SELECT 
                hours.hour,
                COUNT(v.id) as vote_count
            FROM hours
            LEFT JOIN vote v ON strftime('%H', v.timestamp) = printf('%02d', hours.hour)
            GROUP BY hours.hour
            ORDER BY hours.hour;
        """))

        # Procedure for getting voter demographics
        db.session.execute(text("""
            CREATE VIEW IF NOT EXISTS voter_demographics AS
            SELECT 
                c.party,
                COUNT(DISTINCT v.user_id) as unique_voters,
                COUNT(v.id) as total_votes,
                ROUND(AVG(CASE 
                    WHEN u.created_at IS NOT NULL 
                    THEN julianday('now') - julianday(u.created_at)
                END), 2) as avg_account_age_days
            FROM candidate c
            LEFT JOIN vote v ON c.id = v.candidate_id
            LEFT JOIN user u ON v.user_id = u.id
            GROUP BY c.party;
        """))

# Additional Indexes for Performance
def create_indexes():
    with app.app_context():
        # Composite index for vote analysis
        db.session.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_vote_analysis 
            ON vote (candidate_id, timestamp);
        """))

        # Index for user activity monitoring
        db.session.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_user_activity 
            ON user (last_login, created_at);
        """))

        # Index for audit log querying
        db.session.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_audit_query 
            ON audit_log (action, timestamp);
        """))

def initialize_database_enhancements():
    print("Initializing database enhancements...")
    create_triggers()
    create_views()
    create_stored_procedures()
    create_indexes()
    print("Database enhancements completed successfully!")

if __name__ == '__main__':
    initialize_database_enhancements() 