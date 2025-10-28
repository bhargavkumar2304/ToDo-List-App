from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from forms import LoginForm, RegisterForm, TaskForm
from models import db, User, Task

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/')
@login_required
def index():
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', tasks=tasks)

@app.route('/add', methods=['POST'])
@login_required
def add():
    form = TaskForm()
    if form.validate_on_submit():
        task = Task(title=form.title.data, user_id=current_user.id)
        db.session.add(task)
        db.session.commit()
        flash('Task added!')
    return redirect(url_for('index'))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    task = Task.query.get_or_404(id)
    if task.user_id != current_user.id:
        flash("You can't edit this task.")
        return redirect(url_for('index'))
    form = TaskForm(obj=task)
    if form.validate_on_submit():
        task.title = form.title.data
        db.session.commit()
        flash('Task updated!')
        return redirect(url_for('index'))
    return render_template('edit.html', form=form)

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    task = Task.query.get_or_404(id)
    if task.user_id == current_user.id:
        db.session.delete(task)
        db.session.commit()
        flash('Task deleted!')
    return redirect(url_for('index'))

@app.route('/complete/<int:id>')
@login_required
def complete(id):
    task = Task.query.get_or_404(id)
    if task.user_id == current_user.id:
        task.completed = not task.completed
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        user = User(username=form.username.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Account created! You can now log in.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
