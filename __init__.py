from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from random import randint
# NON PRODUCTION VERSION, PROVIDE FEEDBACK IF NEEDED. PLEASE FOLLOW PEP8 TYPING GUIDELINES IF YOU ARE EDITING THIS!
# CONFIG
# CONFIG WILL BE MOVED TO A SEPARATE FILE WHEN PUSHED FOR BLUEPRINTING!
app = Flask(__name__)
app.config['SECRET_KEY'] = 'changethisondeployment.'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    verify = db.Column(db.String(5))
    # verified is the email verification flag, 0 is not verified. 1 is verified by email.
    verified = db.Column(db.Integer)
    perm = db.Column(db.Integer)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class VerifyForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    verify = StringField('code', validators=[InputRequired(), Length(max=5)])


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

# END OF CONFIG


@app.route('/')
def index():
    return redirect('/login')


# START OF LOGIN SECTION


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user:
                if check_password_hash(user.password, form.password.data):
                    if user.verified == 0:
                      return redirect('/verify')
                    else:
                      login_user(user, remember=form.remember.data)
                      return redirect('/dashboard')
        flash("invalid login!")
        return render_template('login.html', form=form)
    else:
        return render_template('login.html', form=form)


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    # OTP mail verification, it was either this or a third party option.
    form = VerifyForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                if user.verify == form.verify.data:
                    try:
                      user.verified = 1
                      db.session.commit()
                      flash("email has been verified")
                      return redirect('login')
                    except:
                        flash("something went wrong, please try again.")
                        return render_template('verify.html', form=form)
                else:
                    flash("invalid code")
                    return render_template('verify.html', form=form)
        flash("invalid code or user")
        return render_template('verify.html', form=form)
    else:
        return render_template('verify.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            hashed_password = generate_password_hash(form.password.data, method='sha256')
            # This is a form of OTP to sent via email, its unique per account and assigned upon register.
            value = randint(1000, 9999)
            new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, verify=str(value), verified=0, perm=0)
            try:
                db.session.add(new_user)
                db.session.commit()
                return redirect('/verify')
            except:
                db.session.rollback()
                return redirect(url_for('signup'))
        else:
            flash("invalid: user already exists, or you did not fill in the proper parameters!")
            return render_template('signup.html', form=form)
    else:
        return render_template('signup.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    # pops a user's session
    return redirect(url_for('index'))


# END OF LOGIN SECTION


if __name__ == '__main__':
    app.run(debug=True)
