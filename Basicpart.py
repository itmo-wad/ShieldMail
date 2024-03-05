from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Use a secure, consistent secret key in production

# MongoDB setup
client = MongoClient('your_mongodb_connection_string')
db = client['auth']  # Your database name
collection = db['forma']  # Your users collection




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = collection.find_one({'username': username})

        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            return redirect(url_for('profile'))
        else:
            flash('Invalid username or password')
    
    return render_template('Login_Page.html')

@app.route('/profile')
def profile():
    if 'user_id' in session:
        user_id = session['user_id']
        user = collection.find_one({"_id": ObjectId(user_id)})

        if user:
            user.pop('password', None)  # Remove the password from the user info
        return render_template('Profile_Info_Page.html', user=user)
    else:
        flash('User not found. Please log in again.')
        return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        first_name = request.form['first_name']
        email = request.form['last_name']
        password = request.form['password']

        user_exists = collection.find_one({'$or': [{'username': username}, {'email': email}]})

        if user_exists:
            flash('Username or email already exists.')
            return redirect(url_for('signup'))
        
        hashed_password = generate_password_hash(password)
        new_user_id = collection.insert_one({
            'username': username,
            'first_name': first_name,
            #'last_name': last_name,
           # 'email': email,
            #'password': hashed_password
        }).inserted_id

        session['user_id'] = str(new_user_id)
        return redirect(url_for('profile'))
    
    return render_template('Sign_Up_Page.html')




@app.route('/signuup')
def default():
    return render_template('Profile_Info_Page.html')

@app.route('/signuup')
def signuup():
    return render_template('Sign_Up_Page.html')

@app.route('/signin')
def signin():
    return render_template('Login_Page.html')

@app.route('/home')
def Home():
    return render_template('Home_Page.html')

@app.route('/infopage')
def profilee():
    return render_template('Profile_Info_Page.html')

@app.route('/emailcheck')
def emailcheck():
    return render_template('Spam_Email_Page.html')

@app.route('/dashboard')
def dashboard():
    return render_template('User_Dashboard_Page.html')

@app.route('/maliciouscheck')
def malicious():
    return render_template('Malicious_Link_Page.html')

if __name__ == "__main__":
    app.run(debug=True)
