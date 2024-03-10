import os
from flask import Flask, render_template, session, redirect, url_for
from dotenv import load_dotenv
from pymongo import MongoClient
from authlib.integrations.flask_client import OAuth
from flask_bcrypt import Bcrypt

load_dotenv()

app = Flask(__name__)

mongo_db_url = os.environ.get('MONGO_DB_CONN_STRING')
client = MongoClient(mongo_db_url)

database_name = os.environ.get('DATABASE_NAME')

db = client[database_name]

bcrypt = Bcrypt(app)

app.secret_key = os.environ.get('SECRET_KEY')

oauth = OAuth(app)

GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY')

oauth.register('shieldmail',
               client_id=os.environ.get('OAUTH2_CLIENT_ID'),
               client_secret=os.environ.get('OAUTH2_CLIENT_SECRET'),
               server_metadata_url=os.environ.get('OAUTH2_META_URL'),
               client_kwargs={
                   'scope': 'openid profile email'})

def register_blueprints(app):
    from views.auth import auth
    from views.core import core
    app.register_blueprint(auth, url_prefix="")
    app.register_blueprint(core, url_prefix="")

@app.route("/")
@app.route("/home")
def home():
    if 'user' in session:
        return redirect(url_for('core.dashboard'))
    
    return render_template('Home_Page.html')

if __name__ == '__main__':
    register_blueprints(app)
    app.run(host='localhost', port=5000, debug=True)