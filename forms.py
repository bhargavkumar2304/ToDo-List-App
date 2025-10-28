from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, SelectField
from wtforms.validators import InputRequired, Length, EqualTo

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=3, max=100)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4)])
    confirm = PasswordField('Confirm Password', validators=[EqualTo('password')])
    submit = SubmitField('Register')


class TaskForm(FlaskForm):
    title = StringField('Task', validators=[InputRequired()])
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[InputRequired()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[InputRequired()])
    priority = SelectField('Priority', choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High')], validators=[InputRequired()])
    submit = SubmitField('Save Task')
