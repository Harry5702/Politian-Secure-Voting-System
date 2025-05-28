from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from sqlalchemy import event, text, func, Index, desc
from sqlalchemy.exc import SQLAlchemyError
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///voting.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Custom template filter for local time conversion
@app.template_filter('to_local_time')
def to_local_time(value):
    if value is None or value == '':
        return 'Never'
    try:
        if isinstance(value, str):
            value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        local_time = value + timedelta(hours=5)
        return local_time.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return 'Never'

# Custom template filter for safe datetime formatting
@app.template_filter('format_datetime')
def format_datetime(value):
    if value is None or value == '':
        return 'Never'
    try:
        if isinstance(value, str):
            value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        local_time = value + timedelta(hours=5)
        return local_time.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return 'Never'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    cnic = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    votes = db.relationship('Vote', backref='voter', lazy=True)
    login_attempts = db.Column(db.Integer, default=0)
    account_locked = db.Column(db.Boolean, default=False)

class Candidate(db.Model):
    __tablename__ = 'candidate'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    party = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    votes = db.relationship('Vote', backref='candidate', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    vote_count = db.Column(db.Integer, default=0)

class Vote(db.Model):
    __tablename__ = 'vote'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    device_info = db.Column(db.String(200))

class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user = db.relationship('User', backref='audit_logs', lazy=True)

# Create indexes after model definitions
with app.app_context():
    db.Index('idx_user_email_username', User.email, User.username)
    db.Index('idx_vote_timestamp', Vote.timestamp)
    db.Index('idx_audit_timestamp', AuditLog.timestamp)
    db.Index('idx_candidate_party', Candidate.party)

# Enhanced Database Triggers
@event.listens_for(Vote, 'after_insert')
def update_vote_statistics(mapper, connection, target):
    # Update candidate vote count
    connection.execute(
        text("UPDATE candidate SET vote_count = vote_count + 1 WHERE id = :candidate_id"),
        {"candidate_id": target.candidate_id}
    )
    
    # Log the vote in audit log
    connection.execute(
        text("""
        INSERT INTO audit_log (user_id, action, details, timestamp, ip_address)
        VALUES (:user_id, 'VOTE', :details, :timestamp, :ip_address)
        """),
        {
            "user_id": target.user_id,
            "details": f"Vote cast for candidate ID {target.candidate_id}",
            "timestamp": datetime.utcnow(),
            "ip_address": target.ip_address
        }
    )

@event.listens_for(User, 'before_update')
def monitor_user_changes(mapper, connection, target):
    if target.login_attempts >= 3:
        target.account_locked = True
        connection.execute(
            text("""
            INSERT INTO audit_log (user_id, action, details, timestamp)
            VALUES (:user_id, 'SECURITY', :details, :timestamp)
            """),
            {
                "user_id": target.id,
                "details": "Account locked due to multiple failed login attempts",
                "timestamp": datetime.utcnow()
            }
        )

# Database Utility Functions
def get_detailed_voting_statistics():
    """Get comprehensive voting statistics with demographic data"""
    try:
        stats = db.session.execute(text("""
            SELECT 
                c.name,
                c.party,
                COUNT(v.id) as vote_count,
                (COUNT(v.id) * 100.0 / NULLIF((SELECT COUNT(*) FROM vote), 0)) as percentage,
                MAX(v.timestamp) as last_vote_time,
                COUNT(DISTINCT v.user_id) as unique_voters
            FROM candidate c
            LEFT JOIN vote v ON c.id = v.candidate_id
            GROUP BY c.id, c.name, c.party
            ORDER BY vote_count DESC
        """))
        return stats
    except SQLAlchemyError as e:
        db.session.rollback()
        return None

def get_hourly_vote_distribution(days=7):
    """Get hourly vote distribution for the last N days"""
    try:
        distribution = db.session.execute(text("""
            SELECT 
                strftime('%H', timestamp) as hour,
                COUNT(*) as vote_count
            FROM vote
            WHERE timestamp >= datetime('now', :days)
            GROUP BY strftime('%H', timestamp)
            ORDER BY hour
        """), {"days": f'-{days} days'})
        return distribution
    except SQLAlchemyError as e:
        db.session.rollback()
        return None

def get_security_audit_report():
    """Get security-related events report"""
    try:
        return db.session.execute(text("""
            SELECT 
                u.username,
                al.action,
                al.details,
                al.timestamp,
                al.ip_address
            FROM audit_log al
            LEFT JOIN user u ON al.user_id = u.id
            WHERE al.action IN ('SECURITY', 'LOGIN_FAILED', 'LOGIN_SUCCESS')
            ORDER BY al.timestamp DESC
            LIMIT 100
        """))
    except SQLAlchemyError as e:
        db.session.rollback()
        return None

# Enhanced User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Utility function to log audit events
def log_audit_event(user_id, action, details, ip_address):
    try:
        audit = AuditLog(
            user_id=user_id,
            action=action,
            details=details,
            ip_address=ip_address
        )
        db.session.add(audit)
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/campaign')
def campaign():
    candidates = Candidate.query.all()
    return render_template('campaign.html', candidates=candidates)

@app.route('/vote')
@login_required
def vote():
    if Vote.query.filter_by(user_id=current_user.id).first():
        flash('You have already voted!', 'warning')
        return redirect(url_for('campaign'))
    candidates = Candidate.query.all()
    return render_template('vote.html', candidates=candidates)

@app.route('/submit_vote/<int:candidate_id>', methods=['POST'])
@login_required
def submit_vote(candidate_id):
    if Vote.query.filter_by(user_id=current_user.id).first():
        flash('You have already voted!', 'warning')
        return redirect(url_for('campaign'))
    
    vote = Vote(user_id=current_user.id, candidate_id=candidate_id)
    db.session.add(vote)
    db.session.commit()
    flash('Your vote has been recorded!', 'success')
    return redirect(url_for('campaign'))

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        cnic = request.form.get('cnic')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(cnic=cnic).first():
            flash('CNIC already registered!', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password, cnic=cnic)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.account_locked:
            flash('Your account has been locked. Please contact support.', 'danger')
            return redirect(url_for('login'))
        
        if user and bcrypt.check_password_hash(user.password, password):
            if user.is_admin:
                flash('Please use the admin login for administrator accounts.', 'warning')
                return redirect(url_for('admin_login'))
            
            login_user(user)
            user.last_login = datetime.utcnow()
            user.login_attempts = 0
            db.session.commit()
            
            log_audit_event(
                user.id,
                'LOGIN_SUCCESS',
                f'Voter login successful for user {username}',
                request.remote_addr
            )
            
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            if user:
                user.login_attempts += 1
                if user.login_attempts >= 3:
                    user.account_locked = True
                    log_audit_event(
                        user.id,
                        'SECURITY',
                        f'Account locked due to multiple failed login attempts for user {username}',
                        request.remote_addr
                    )
                    flash('Your account has been locked due to multiple failed attempts. Please contact support.', 'danger')
                else:
                    log_audit_event(
                        user.id,
                        'LOGIN_FAILED',
                        f'Failed login attempt for user {username} (Attempt {user.login_attempts} of 3)',
                        request.remote_addr
                    )
                    flash(f'Invalid username or password! {3 - user.login_attempts} attempts remaining.', 'danger')
                db.session.commit()
            else:
                flash('Invalid username or password!', 'danger')
    
    return render_template('login.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.account_locked:
            flash('Your account has been locked. Please contact the system administrator.', 'danger')
            return redirect(url_for('admin_login'))
        
        if user and bcrypt.check_password_hash(user.password, password):
            if not user.is_admin:
                flash('This login is for administrators only. Please use the voter login.', 'warning')
                return redirect(url_for('login'))
            
            login_user(user)
            user.last_login = datetime.utcnow()
            user.login_attempts = 0
            db.session.commit()
            
            log_audit_event(
                user.id,
                'ADMIN_LOGIN',
                f'Administrator login successful for {username}',
                request.remote_addr
            )
            
            flash('Administrator login successful!', 'success')
            return redirect(url_for('admin'))
        else:
            if user:
                user.login_attempts += 1
                if user.login_attempts >= 3:
                    user.account_locked = True
                    log_audit_event(
                        user.id,
                        'SECURITY',
                        f'Admin account locked due to multiple failed login attempts for user {username}',
                        request.remote_addr
                    )
                    flash('Your account has been locked due to multiple failed attempts. Please contact system administrator.', 'danger')
                else:
                    log_audit_event(
                        user.id,
                        'ADMIN_LOGIN_FAILED',
                        f'Failed administrator login attempt for {username} (Attempt {user.login_attempts} of 3)',
                        request.remote_addr
                    )
                    flash(f'Invalid administrator credentials! {3 - user.login_attempts} attempts remaining.', 'danger')
                db.session.commit()
            else:
                flash('Invalid administrator credentials!', 'danger')
    
    return render_template('admin_login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied!', 'danger')
        return redirect(url_for('home'))
    
    votes = Vote.query.all()
    candidates = Candidate.query.all()
    users = User.query.all()
    return render_template('admin.html', votes=votes, candidates=candidates, users=users)

@app.route('/admin/analytics')
@login_required
def admin_analytics():
    if not current_user.is_admin:
        flash('Access denied!', 'danger')
        return redirect(url_for('home'))
    
    try:
        # Get voting statistics with proper percentage calculation
        stats_query = text("""
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
            ORDER BY vote_count DESC
        """)
        stats_result = db.session.execute(stats_query).fetchall()
        
        # Convert stats results to list of dictionaries
        stats = [
            {
                'name': row.name,
                'party': row.party,
                'vote_count': row.vote_count,
                'percentage': float(row.percentage) if row.percentage is not None else 0.0
            }
            for row in stats_result
        ]

        # Get user activity data with proper NULL handling and timezone conversion
        activity_query = text("""
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
            GROUP BY u.id, u.username, u.email, u.last_login
            ORDER BY last_vote DESC NULLS LAST
        """)
        activity_result = db.session.execute(activity_query).fetchall()
        
        # Convert activity results to list of dictionaries with proper NULL handling
        activity = [
            {
                'username': row.username,
                'email': row.email,
                'vote_count': row.vote_count or 0,
                'last_vote': row.last_vote if row.last_vote else None,
                'last_login': row.last_login if row.last_login else None
            }
            for row in activity_result
        ]

        return render_template('admin_analytics.html', 
                            stats=stats,
                            activity=activity)
    except SQLAlchemyError as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('admin'))

@app.route('/admin/audit-log')
@login_required
def audit_log():
    if not current_user.is_admin:
        flash('Access denied!', 'danger')
        return redirect(url_for('home'))
    
    try:
        # Join with User table to get usernames and adjust timestamps to local time
        audit_query = text("""
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
            LIMIT 100
        """)
        logs = db.session.execute(audit_query).fetchall()
        return render_template('audit_log.html', logs=logs)
    except SQLAlchemyError as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('admin'))

@app.route('/admin/db-stats')
@login_required
def database_statistics():
    if not current_user.is_admin:
        flash('Access denied!', 'danger')
        return redirect(url_for('home'))
    
    detailed_stats = get_detailed_voting_statistics()
    hourly_dist = get_hourly_vote_distribution()
    security_report = get_security_audit_report()
    
    return render_template(
        'admin/db_stats.html',
        detailed_stats=detailed_stats,
        hourly_dist=hourly_dist,
        security_report=security_report
    )

@app.route('/admin/api/vote-trends')
@login_required
def vote_trends():
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        trends = db.session.execute(text("""
            SELECT 
                date(timestamp) as vote_date,
                COUNT(*) as vote_count
            FROM vote
            WHERE timestamp >= date('now', '-30 days')
            GROUP BY date(timestamp)
            ORDER BY vote_date
        """))
        
        return jsonify({
            'dates': [str(row.vote_date) for row in trends],
            'counts': [row.vote_count for row in trends]
        })
    except SQLAlchemyError as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/api/overview-stats')
@login_required
def overview_stats():
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        total_votes = db.session.query(func.count(Vote.id)).scalar()
        active_users = db.session.query(func.count(User.id))\
            .filter(User.last_login >= (datetime.utcnow() - timedelta(days=7))).scalar()
        total_candidates = db.session.query(func.count(Candidate.id)).scalar()
        security_events = db.session.query(func.count(AuditLog.id))\
            .filter(AuditLog.action.in_(['SECURITY', 'LOGIN_FAILED'])).scalar()
        
        return jsonify({
            'total_votes': total_votes,
            'active_users': active_users,
            'total_candidates': total_candidates,
            'security_events': security_events
        })
    except SQLAlchemyError as e:
        return jsonify({'error': str(e)}), 500

# New Analytics Routes using Enhanced Database Features
@app.route('/admin/detailed-stats')
@login_required
def detailed_stats():
    if not current_user.is_admin:
        flash('Access denied!', 'danger')
        return redirect(url_for('home'))
    
    try:
        # Using the detailed_voting_stats view
        stats = db.session.execute(text("SELECT * FROM detailed_voting_stats"))
        
        # Using the voter_demographics view
        demographics = db.session.execute(text("SELECT * FROM voter_demographics"))
        
        # Using the hourly_vote_distribution view
        hourly_dist = db.session.execute(text("SELECT * FROM hourly_vote_distribution"))
        
        return render_template(
            'admin/detailed_stats.html',
            stats=stats,
            demographics=demographics,
            hourly_dist=hourly_dist
        )
    except SQLAlchemyError as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('admin'))

@app.route('/admin/user-patterns')
@login_required
def user_patterns():
    if not current_user.is_admin:
        flash('Access denied!', 'danger')
        return redirect(url_for('home'))
    
    try:
        # Using the user_voting_patterns view
        patterns = db.session.execute(text("SELECT * FROM user_voting_patterns"))
        return render_template('admin/user_patterns.html', patterns=patterns)
    except SQLAlchemyError as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('admin'))

@app.route('/admin/api/voting-analytics')
@login_required
def voting_analytics():
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        # Complex join query for detailed analytics
        analytics = db.session.execute(text("""
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
            ORDER BY total_votes DESC
        """))
        
        return jsonify({
            'candidates': [dict(row) for row in analytics]
        })
    except SQLAlchemyError as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/audit-analytics')
@login_required
def audit_analytics():
    if not current_user.is_admin:
        flash('Access denied!', 'danger')
        return redirect(url_for('home'))
    
    try:
        # Complex query using joins and window functions
        audit_stats = db.session.execute(text("""
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
            ORDER BY audit_date DESC
        """))
        
        return render_template('admin/audit_analytics.html', audit_stats=audit_stats)
    except SQLAlchemyError as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('admin'))

@app.route('/admin/realtime-stats')
@login_required
def realtime_stats():
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        # Get total votes
        total_votes = db.session.query(func.count(Vote.id)).scalar()
        
        # Get votes today
        votes_today = db.session.query(func.count(Vote.id))\
            .filter(Vote.timestamp >= datetime.now().replace(hour=0, minute=0, second=0, microsecond=0))\
            .scalar()
        
        # Get active users (users who voted in the last hour)
        active_users = db.session.query(func.count(func.distinct(Vote.user_id)))\
            .filter(Vote.timestamp >= datetime.now() - timedelta(hours=1))\
            .scalar()
        
        return jsonify({
            'total_votes': total_votes or 0,
            'votes_today': votes_today or 0,
            'active_users': active_users or 0
        })
    except SQLAlchemyError as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Initialize database enhancements
        from database_enhancements import initialize_database_enhancements
        initialize_database_enhancements()
    app.run(debug=True) 