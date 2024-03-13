from flask import Response, request, jsonify, url_for, session, redirect, Blueprint, render_template,flash
from functools import wraps
from bson.json_util import dumps
from bson.objectid import ObjectId
from flask_wtf import FlaskForm
from models.mailanalyzer import EmailAnalyzer
from models.forms import SpamMail
from main import GOOGLE_API_KEY
from main import db
import os
import re
import requests
import bleach
from datetime import datetime
import json

core = Blueprint("core", __name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@core.route("/dashboard")
def dashboard():
    if 'user' in session:
        return render_template('User_Dashboard.html')
    
    return redirect(url_for('home'))

@core.route('/profile',methods=['GET'])
@login_required
def profile():
    if request.method == 'GET':
        email = session['user']['email']
        user = db.users.find_one({'email': email})

        return render_template('Profile_Info_Page.html',
                               user=user)

@login_required
@core.route('/spam-email', methods=['GET', 'POST'])
def spamEmail():
    
    form = SpamMail()
    if form.validate_on_submit():
        email = session['user']['email']
        user = db.users.find_one({'email': email})
        user_id = user['_id']

        content = form.content.data
        sanitized_content = bleach.clean(content)

        email_analyzer = EmailAnalyzer(GOOGLE_API_KEY,sanitized_content)

        urls = email_analyzer.included_urls()

        url_ids = []
        for url in urls:
            isMalicious = email_analyzer.detect_phishing()
            
            url_to_add = db.urls.insert_one({
                'url': url,
                'isMalicious': isMalicious,
                'owner': ObjectId(user_id),
                'createdAt': datetime.now()
            })

            url_ids.append(url_to_add.inserted_id)

        email = db.emails.insert_one({
            'content': sanitized_content,
            'phishingDetected': email_analyzer.detect_phishing(),
            'spamDetected': email_analyzer.detect_spam(),
            'lexicalDiversity': email_analyzer.lexical_diversity(),
            'grammarIssues': email_analyzer.grammar_checker(),
            'fleschReadingEase': email_analyzer.flesch_reading_ease(),
            'toxicityScore': email_analyzer.toxicity_score(),
            'spamScore': email_analyzer.spam_score(),
            'incoherentScore': email_analyzer.incoherence_score(),
            'riskScore': email_analyzer.calculate_risk_score(),
            'owner': ObjectId(user_id),
            'urls': url_ids,
            'createdAt': datetime.now()
        })

        email = db.emails.find_one({'_id': email.inserted_id})

        email['_id'] = str(email['_id'])
        email['owner'] = str(email['owner'])
        for i in range(len(email['urls'])):
            url = db.urls.find_one({'_id': email['urls'][i]})
            url['_id'] = str(url['_id'])
            url['owner'] = str(url['owner'])

            email['urls'][i] = url

        return jsonify(email)
        
    return render_template('Spam_Email_Page.html', form=form)

@core.route('/maliciouslinkcheck',methods=['GET', 'POST'])
@login_required
def maliciouslinkcheck():
    if request.method == 'GET':
        return render_template('Malicious_Link_Page.html')
    
    if request.method == 'POST':
        user = db.users.find_one({'email': session['user']['email']})

        data = request.get_json()
        malicious_link = bleach.clean(data.get('link'))

        email_analyzer = EmailAnalyzer(GOOGLE_API_KEY,malicious_link)
        phishingDetected = email_analyzer.detect_phishing()

        db.urls.insert_one({
            'userId': ObjectId(user['_id']),
            'maliciousLink': malicious_link,
            'isMalicious': phishingDetected,
            'dateChecked': datetime.now()
        })

        # Ensure you return the same key as expected by JavaScript
        return jsonify({'isMalicious': phishingDetected})
        pass

@core.route('/history',methods=['GET'])
@login_required
def historyLink():
    if request.method == 'GET':
        user = db.users.find_one({'email':session['user']['email']})
        urls = db.urls.find({'userId':ObjectId(user['_id'])})
        urls_list=list(urls)
        for hist in urls_list:
            hist['dateChecked'] = hist['dateChecked'].strftime('%d.%m.%Y %H:%M:%S')
        return render_template('History_Page.html',urls=urls_list)

@core.route('/historyMessage',methods=['GET'])
@login_required
def historyMessage():
    if request.method == 'GET':
        user = db.users.find_one({'email':session['user']['email']})
        emails = db.emails.find({'owner':ObjectId(user['_id'])})
        emails_list=list(emails)
        for hist in emails_list:
            hist['createdAt'] = hist['createdAt'].strftime('%d.%m.%Y %H:%M:%S')
        return render_template('History_Page_Email.html',emails=emails_list)



