from flask import Flask, redirect, url_for, render_template, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from datetime import timedelta
import os.path

### REFS ###
# https://www.youtube.com/watch?v=71EU8gnZqZQ
# https://github.com/arpanneupane19/Python-Flask-Authentication-Tutorial/blob/main/app.py
# https://stackoverflow.com/questions/73961938/flask-sqlalchemy-db-create-all-raises-runtimeerror-working-outside-of-applicat
# https://www.digitalocean.com/community/tutorials/how-to-use-flask-sqlalchemy-to-interact-with-databases-in-a-flask-application
# https://flask-sqlalchemy.palletsprojects.com/en/2.x/quickstart/
# https://flask-login.readthedocs.io/en/latest/#login-example
# https://www.patricksoftwareblog.com/changing-users-password/
###

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
#app.secret_key = "test"
app.permanent_session_lifetime = timedelta(minutes=5)
app.config['SQLALCHEMY_DATABASE_URI'] =\
        'sqlite:///' + os.path.join(basedir, 'database.db')
db = SQLAlchemy(app)
app.config['SECRET_KEY'] = 'thisISaSECRETkey'
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), nullable = False, unique = True)
    password = db.Column(db.String(80), nullable = False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

class ChangePwForm(FlaskForm):
    oldpass = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Current password"})
    newpass = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "New password"})
    confirmpass = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Confirm password"})
    submit = SubmitField('Change')



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# HOME PAGE
@app.route("/")
def home():
	return render_template("index.html")

#LOGIN PAGE
@app.route("/login/", methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                flash("Login Successful!")
                return redirect(url_for('user'))
        flash("Username or password incorrect", "info")
    return render_template('login.html', form=form)

#USER PAGE
@app.route("/user/")
@login_required
def user():
    user = current_user.username
    return render_template("user.html", usr=user)
 
 #LOGOUT PAGE
@app.route('/logout/', methods=['GET', 'POST'])
@login_required
def logout():
    user = current_user.username
    logout_user()
    flash(f"You have been logged out, {user}", "success")
    return redirect(url_for('login'))

#REGISTRATION PAGE
@app.route('/register/', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

#CHANGE PASSWORD PAGE
@app.route('/changepw/', methods=['GET', 'POST'])
@login_required
def changepw():
    form = ChangePwForm()
    if form.validate_on_submit():
        user = current_user
        if bcrypt.check_password_hash(user.password, form.oldpass.data):
            if form.newpass.data == form.confirmpass.data:
                user.password = bcrypt.generate_password_hash(form.newpass.data)
                db.session.add(user)
                db.session.commit()
                flash('Your password has been updated', 'success')
                logout_user()
            else:
                flash('Your passwords did not match', 'info')
            return redirect(url_for('login'))
    return render_template('changepw.html', form=form)

if __name__ == "__main__":
    app.run(debug=True)
