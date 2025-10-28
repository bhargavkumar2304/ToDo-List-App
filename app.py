from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from forms import LoginForm, RegisterForm, TaskForm
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    tasks = db.relationship('Task', backref='author', lazy=True)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    start_date = db.Column(db.Date, nullable=True)
    end_date = db.Column(db.Date, nullable=True)
    priority = db.Column(db.String(20), nullable=False, default='Low')
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# Routes
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out!', 'info')
    return redirect(url_for('login'))


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    form = TaskForm()
    if form.validate_on_submit():
        if not form.start_date.data or not form.end_date.data:
            flash('Please select both start and end dates for the task.', 'danger')
            return redirect(url_for('index'))

        if form.end_date.data < form.start_date.data:
            flash('End date must be later than or equal to the start date.', 'danger')
            return redirect(url_for('index'))

        if not form.priority.data:
            flash('Please select a priority for the task.', 'danger')
            return redirect(url_for('index'))

        task = Task(
            title=form.title.data,
            start_date=form.start_date.data,
            end_date=form.end_date.data,
            priority=form.priority.data,
            user_id=current_user.id
        )
        db.session.add(task)
        db.session.commit()
        flash('Task added successfully!', 'success')
        return redirect(url_for('index'))

    tasks = Task.query.filter_by(user_id=current_user.id).all()
    current_date = datetime.today().date()

    return render_template('index.html', form=form, tasks=tasks, current_date=current_date)


@app.route('/complete/<int:id>')
@login_required
def complete(id):
    task = Task.query.get_or_404(id)
    task.completed = True
    db.session.commit()
    flash('Task marked as completed!', 'success')
    return redirect(url_for('index'))


@app.route('/delete/<int:id>')
@login_required
def delete(id):
    task = Task.query.get_or_404(id)
    db.session.delete(task)
    db.session.commit()
    flash('Task deleted!', 'info')
    return redirect(url_for('index'))


@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    task = Task.query.get_or_404(id)
    form = TaskForm(obj=task)
    if form.validate_on_submit():
        if not form.start_date.data or not form.end_date.data:
            flash('Please select both start and end dates for the task.', 'danger')
            return redirect(url_for('edit', id=id))

        if form.end_date.data < form.start_date.data:
            flash('End date must be later than or equal to the start date.', 'danger')
            return redirect(url_for('edit', id=id))

        if not form.priority.data:
            flash('Please select a priority for the task.', 'danger')
            return redirect(url_for('edit', id=id))

        task.title = form.title.data
        task.start_date = form.start_date.data
        task.end_date = form.end_date.data
        task.priority = form.priority.data
        db.session.commit()
        flash('Task updated successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('edit.html', form=form, task=task)


if __name__ == '__main__':
    app.run(debug=True)
