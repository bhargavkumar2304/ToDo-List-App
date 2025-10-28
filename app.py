import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# --- Flask app setup ---
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'

# --- Initialize DB ---
db = SQLAlchemy(app)

# --- Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    tasks = db.relationship('Task', backref='user', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    completed = db.Column(db.Boolean, default=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- User loader ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- Routes ---
@app.route('/')
@login_required
def index():
    tasks = Task.query.filter_by(user_id=current_user.id).order_by(Task.date_created.desc()).all()
    return render_template('index.html', tasks=tasks)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Login now.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        flash('Invalid credentials!', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/add', methods=['POST'])
@login_required
def add_task():
    title = request.form['title']
    description = request.form.get('description')
    if not title:
        flash('Task title cannot be empty!', 'danger')
        return redirect(url_for('index'))
    task = Task(title=title, description=description, user_id=current_user.id)
    db.session.add(task)
    db.session.commit()
    flash('Task added successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/edit/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        flash("You can't edit this task!", 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        task.title = request.form['title']
        task.description = request.form.get('description')
        db.session.commit()
        flash('Task updated!', 'success')
        return redirect(url_for('index'))
    return render_template('edit.html', task=task)

@app.route('/delete/<int:task_id>')
@login_required
def delete(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        flash("You can't delete this task!", 'danger')
        return redirect(url_for('index'))
    db.session.delete(task)
    db.session.commit()
    flash('Task deleted!', 'info')
    return redirect(url_for('index'))

@app.route('/complete/<int:task_id>')
@login_required
def complete(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        flash("You can't modify this task!", 'danger')
        return redirect(url_for('index'))
    task.completed = not task.completed
    db.session.commit()
    flash('Task status updated!', 'success')
    return redirect(url_for('index'))

# --- Run the app ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure DB tables exist
    app.run(debug=True, port=5001)
