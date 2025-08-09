"""
This module implements a simple job board web application for healthcare
staffing.  It uses Flask for the web framework, SQLAlchemy as the ORM,
and Flask‑Login for session management.  The goal is to demonstrate the
core features requested by the user: allowing employers to post jobs,
allowing candidates to create accounts and apply for jobs, and sending
simple job alerts when new postings match saved criteria.  For
illustrative purposes the email functionality simply prints to the
console; in a production system you would integrate with an email
service such as SendGrid or Amazon SES.

The application stores data in a SQLite database.  To run the app,
install the dependencies (Flask, Flask‑Login, Flask‑SQLAlchemy) and
start the server with `python app.py`.  Visit the root URL in your
browser to use the site.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from flask import (Flask, flash, redirect, render_template, request,
                   url_for)
from flask_login import (LoginManager, UserMixin, current_user,
                         login_required, login_user, logout_user)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'change-me-please'  # In production use a secure secret
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///job_board.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


###########################################################################
# Database models
###########################################################################

class User(UserMixin, db.Model):
    """Represents a registered user (employer or job seeker)."""
    id: int = db.Column(db.Integer, primary_key=True)
    username: str = db.Column(db.String(80), unique=True, nullable=False)
    email: str = db.Column(db.String(120), unique=True, nullable=False)
    password_hash: str = db.Column(db.String(128), nullable=False)
    role: str = db.Column(db.String(20), nullable=False)  # 'employer' or 'seeker'
    # Relationships
    jobs = db.relationship('Job', backref='creator', lazy=True)
    applications = db.relationship('Application', backref='candidate', lazy=True)
    alerts = db.relationship('JobAlert', backref='subscriber', lazy=True)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Job(db.Model):
    """Represents a job posting created by an employer."""
    id: int = db.Column(db.Integer, primary_key=True)
    title: str = db.Column(db.String(120), nullable=False)
    description: str = db.Column(db.Text, nullable=False)
    location: str = db.Column(db.String(120), nullable=False)
    job_type: str = db.Column(db.String(50), nullable=False)
    qualifications: str = db.Column(db.Text, nullable=True)
    # Additional fields for enhanced job postings
    # Name of the hospital, facility or company offering the position
    company_name: str = db.Column(db.String(120), nullable=True)
    # Point of contact for the job listing
    contact_name: str = db.Column(db.String(120), nullable=True)
    contact_email: str = db.Column(db.String(120), nullable=True)
    # Pay rate or salary offered for the role. Stored as a simple string
    pay_rate: str = db.Column(db.String(100), nullable=True)
    # Additional notes provided by the employer
    notes: str = db.Column(db.Text, nullable=True)
    created_at: datetime = db.Column(db.DateTime, default=datetime.utcnow)
    created_by: int = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    applications = db.relationship('Application', backref='job', lazy=True)


class Application(db.Model):
    """Represents a job application submitted by a job seeker."""
    id: int = db.Column(db.Integer, primary_key=True)
    job_id: int = db.Column(db.Integer, db.ForeignKey('job.id'), nullable=False)
    user_id: int = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    resume_text: str = db.Column(db.Text, nullable=False)
    cover_letter: str = db.Column(db.Text, nullable=True)
    created_at: datetime = db.Column(db.DateTime, default=datetime.utcnow)


class JobAlert(db.Model):
    """Represents a saved search/job alert subscription by a job seeker."""
    id: int = db.Column(db.Integer, primary_key=True)
    user_id: int = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    keywords: str = db.Column(db.String(200), nullable=True)
    location: str = db.Column(db.String(120), nullable=True)
    job_type: str = db.Column(db.String(50), nullable=True)


###########################################################################
# Login manager
###########################################################################

@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    return User.query.get(int(user_id))


###########################################################################
# Utility functions
###########################################################################

def send_email(to_address: str, subject: str, message: str) -> None:
    """Placeholder email function.

    In a real application this function would integrate with an external
    email provider such as SendGrid, Mailgun or Amazon SES.  For this
    demonstration it simply prints the email contents to the console.
    """
    print(f"\n--- Sending Email ---\nTo: {to_address}\nSubject: {subject}\n{message}\n---------------------\n")


def trigger_job_alerts(new_job: Job) -> None:
    """Notify subscribers when a new job matches their saved criteria.

    For each job alert subscription, if the new job's title, location
    or job_type matches the subscriber's criteria (case insensitive),
    send a notification email.  In a full implementation you would also
    support more advanced matching logic and maybe queue notifications
    for asynchronous delivery.
    """
    alerts = JobAlert.query.all()
    for alert in alerts:
        # Basic matching: check if keyword appears in title, location matches,
        # or job type matches (case insensitive).  Empty criteria are treated
        # as wildcards.
        match_keyword = (not alert.keywords) or (alert.keywords.lower() in new_job.title.lower())
        match_location = (not alert.location) or (alert.location.lower() in new_job.location.lower())
        match_type = (not alert.job_type) or (alert.job_type.lower() == new_job.job_type.lower())
        if match_keyword and match_location and match_type:
            user = alert.subscriber
            subject = f"New job posted: {new_job.title}"
            message = (
                f"Hi {user.username},\n\n"
                f"A new job that matches your saved search has been posted on the job board:\n\n"
                f"Title: {new_job.title}\n"
                f"Location: {new_job.location}\n"
                f"Type: {new_job.job_type}\n\n"
                f"Visit the site to view details and apply."
            )
            send_email(user.email, subject, message)


###########################################################################
# Routes
###########################################################################

@app.route('/')
def home():
    """Home page with introduction and navigation."""
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration for both employers and job seekers."""
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        role = request.form['role']  # 'employer' or 'seeker'
        if not username or not email or not password:
            flash('All fields are required.', 'danger')
        elif User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists.', 'danger')
        else:
            # Create the user and save to the database
            user = User(username=username, email=email, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            # If the new user is an employer, log them in and take them directly to the job posting page
            if role == 'employer':
                login_user(user)
                flash('Registration successful. You can now post a job.', 'success')
                return redirect(url_for('post_job'))
            # Otherwise ask them to log in normally
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login."""
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            # Employers go directly to the job posting page, job seekers go to home/next
            if user.role == 'employer':
                return redirect(url_for('post_job'))
            else:
                return redirect(request.args.get('next') or url_for('home'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Log the current user out."""
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))


@app.route('/post-job', methods=['GET', 'POST'])
@login_required
def post_job():
    """Allow an employer to post a new job."""
    if current_user.role != 'employer':
        flash('Only employers can post jobs.', 'danger')
        return redirect(url_for('jobs'))
    if request.method == 'POST':
        # Retrieve form fields and strip whitespace
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        location = request.form['location'].strip()
        job_type = request.form['job_type'].strip()
        qualifications = request.form.get('qualifications', '').strip()
        company_name = request.form.get('company_name', '').strip()
        contact_name = request.form.get('contact_name', '').strip()
        contact_email = request.form.get('contact_email', '').strip()
        pay_rate = request.form.get('pay_rate', '').strip()
        notes = request.form.get('notes', '').strip()

        # Validate required fields. In addition to title/description/location/job_type
        # we require the employer to provide a company/facility name and a contact email
        if not title or not description or not location or not job_type or not company_name or not contact_email:
            flash('Please fill out all required fields.', 'danger')
        else:
            # Create the job record with extended attributes
            job = Job(
                title=title,
                description=description,
                location=location,
                job_type=job_type,
                qualifications=qualifications,
                company_name=company_name or None,
                contact_name=contact_name or None,
                contact_email=contact_email or None,
                pay_rate=pay_rate or None,
                notes=notes or None,
                creator=current_user
            )
            db.session.add(job)
            db.session.commit()
            flash('Job posted successfully.', 'success')
            # Trigger alerts for subscribers
            trigger_job_alerts(job)
            return redirect(url_for('jobs'))
    return render_template('post_job.html')


@app.route('/jobs')
def jobs():
    """List all job postings with optional filters."""
    # Basic filtering
    search = request.args.get('search', '').strip()
    location = request.args.get('location', '').strip()
    job_type = request.args.get('job_type', '').strip()
    query = Job.query
    if search:
        # search by title or description
        ilike_pattern = f"%{search}%"
        query = query.filter((Job.title.ilike(ilike_pattern)) | (Job.description.ilike(ilike_pattern)))
    if location:
        query = query.filter(Job.location.ilike(f"%{location}%"))
    if job_type:
        query = query.filter(Job.job_type.ilike(job_type))
    jobs = query.order_by(Job.created_at.desc()).all()
    return render_template('jobs.html', jobs=jobs)


@app.route('/job/<int:job_id>', methods=['GET', 'POST'])
def job_detail(job_id: int):
    """View a single job and allow application submission."""
    job = Job.query.get_or_404(job_id)
    if request.method == 'POST':
        if not current_user.is_authenticated or current_user.role != 'seeker':
            flash('You must log in as a job seeker to apply.', 'danger')
            return redirect(url_for('login', next=url_for('job_detail', job_id=job_id)))
        resume_text = request.form['resume'].strip()
        cover_letter = request.form.get('cover_letter', '').strip()
        if not resume_text:
            flash('Please include a resume.', 'danger')
        else:
            application = Application(job=job, candidate=current_user,
                                     resume_text=resume_text, cover_letter=cover_letter)
            db.session.add(application)
            db.session.commit()
            flash('Application submitted successfully.', 'success')
            # Notify employer via email (placeholder)
            subject = f"New application for {job.title}"
            message = (
                f"An applicant ({current_user.username}) has applied for your job posting.\n"
                f"Visit the employer dashboard to review the application."
            )
            send_email(job.creator.email, subject, message)
            return redirect(url_for('jobs'))
    return render_template('job_detail.html', job=job)


@app.route('/alerts', methods=['GET', 'POST'])
@login_required
def alerts():
    """Allow job seekers to create and manage job alerts."""
    if current_user.role != 'seeker':
        flash('Only job seekers can manage alerts.', 'danger')
        return redirect(url_for('jobs'))
    if request.method == 'POST':
        keywords = request.form.get('keywords', '').strip() or None
        location = request.form.get('location', '').strip() or None
        job_type = request.form.get('job_type', '').strip() or None
        alert = JobAlert(subscriber=current_user, keywords=keywords,
                         location=location, job_type=job_type)
        db.session.add(alert)
        db.session.commit()
        flash('Alert created successfully.', 'success')
    alerts_list = JobAlert.query.filter_by(user_id=current_user.id).all()
    return render_template('alerts.html', alerts=alerts_list)


@app.route('/alerts/delete/<int:alert_id>', methods=['POST'])
@login_required
def delete_alert(alert_id: int):
    """Delete a specific job alert."""
    alert = JobAlert.query.get_or_404(alert_id)
    if alert.user_id != current_user.id:
        flash('You do not have permission to delete this alert.', 'danger')
        return redirect(url_for('alerts'))
    db.session.delete(alert)
    db.session.commit()
    flash('Alert deleted.', 'success')
    return redirect(url_for('alerts'))


###########################################################################
# Command line entry point
###########################################################################

if __name__ == '__main__':
    # Create database tables if they do not exist
    with app.app_context():
        db.create_all()
    # Run the Flask development server
    app.run(host='0.0.0.0', port=5000, debug=True)