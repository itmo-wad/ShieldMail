from flask import request, url_for, session, Blueprint, render_template, redirect, flash
from functools import wraps
from models.forms import LoginForm,SignupForm
import requests
from datetime import datetime

from main import db, oauth, bcrypt

auth = Blueprint("auth", __name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('core.dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = db.users.find_one({'email': email})

        if user:
            if bcrypt.check_password_hash(user['password'], password):
                session['user'] = {'email': user['email']}
                db.users.update_one({'email': email}, {'$set': {'lastLogin': datetime.now()}})
                return redirect(url_for('core.dashboard'))
            else:
                flash('Invalid email or password')
                return redirect(url_for('auth.login'))
        else:
            flash('Invalid email or password')
            return redirect(url_for('auth.login'))
        
    return render_template('Login_Page.html', form=form)

@auth.route('/google-login')
def googleLogin():
    return oauth.shieldmail.authorize_redirect(redirect_uri=url_for('auth.googleCallback', _external=True))

@auth.route('/signin-google')
def googleCallback():
    token = oauth.shieldmail.authorize_access_token()

    session['user'] = {'email': token['userinfo']['email'],
                       'access_token': token['access_token']}
    
    email = session['user']['email']
    firstname = token['userinfo']['given_name']
    lastname = token['userinfo']['family_name']
    user = db.users.find_one({'email': email})

    if user is None:
        user = {
            'firstname': firstname,
            'lastname': lastname,
            'email': email,
            'lastLogin': datetime.now(),
            'memberSince': datetime.now()
            }
        db.users.insert_one(user)

    return redirect(url_for('core.dashboard'))

@auth.route('/logout')
def logout():
    if 'user' not in session:
        return redirect(url_for('home'))

    if 'access_token' in session['user']:
        access_token = session['user']['access_token']

        requests.get(
            'https://accounts.google.com/o/oauth2/revoke',
            params={'token': access_token},
            headers = {'content-type': 'application/x-www-form-urlencoded'}
        )

    session.pop('user', None)
    return redirect(url_for('home'))

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user' in session:
        return redirect(url_for('core.dashboard'))
    
    form = SignupForm()
    if form.validate_on_submit():
        firstname = form.firstname.data
        lastname = form.lastname.data
        email = form.email.data
        password = form.password.data

        user = db.users.find_one({'email': email})
        if user is not None:
            flash('Email is already exist')
            return redirect(url_for('auth.signup'))

        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            db.users.insert_one({
                'firstname': firstname,
                'lastname': lastname,
                'email': email,
                'password': hashed_password,
                'lastLogin': datetime.now(),
                'memberSince': datetime.now()
            })

            flash('Registered successfully')
            return redirect(url_for('auth.login'))
        
    return render_template('Sign_Up_Page.html', form=form)
