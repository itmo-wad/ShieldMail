from flask import Response, request, jsonify, url_for, session, redirect, Blueprint, render_template
from bson.json_util import dumps
from bson.objectid import ObjectId
from flask_wtf import FlaskForm
from wtforms import TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length
from ShieldMail.src.models.mailanalyzer import EmailAnalyzer
from ShieldMail.src.main import GOOGLE_API_KEY
from main import db
import os
import re
import requests
import bleach
from datetime import datetime
import json

core = Blueprint("core", __name__)

class SpamMail(FlaskForm):
    content = TextAreaField('Content', validators=[DataRequired(), Length(max=5000)])
    submit = SubmitField('Submit')

@core.route("/dashboard")
def dashboard():
    if 'user' in session:
        return render_template('User_Dashboard.html')
    
    return redirect(url_for('home'))

@core.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('auth.login'))
    
    if request.method == 'GET':
        email = session['user']['email']

        user = db.users.find_one({'email': email})
        firstname = '' if 'firstname' not in user else user['firstname']
        lastname = '' if 'lastname' not in user else user['lastname']
        print(email, firstname, lastname)

        return render_template('Profile_Info_Page.html',
                               email=email,
                               firstname=firstname,
                               lastname=lastname)
    
    if request.method == 'POST':
        pass

@core.route('/spam-email', methods=['GET', 'POST'])
def spamEmail():
    if 'user' not in session:
        return redirect(url_for('auth.login'))
    
    form = SpamMail()
    if form.validate_on_submit():
        email = session['user']['email']
        user = db.users.find_one({'email': email})
        user_id = user['_id']

        content = form.content.data
        email_analyzer = EmailAnalyzer(GOOGLE_API_KEY)

        urls = email_analyzer.included_urls(content)

        url_ids = []
        for url in urls:
            isMalicious = email_analyzer.detect_phishing(url)
            
            url_to_add = db.urls.insert_one({
                'url': url,
                'isMalicious': isMalicious,
                'owner': ObjectId(user_id),
                'createdAt': datetime.now()
            })

            url_ids.append(url_to_add.inserted_id)

        sanitized_content = bleach.clean(content)

        toxicity_score, spam_score, incoherent_score = email_analyzer.analyze_text_with_perspective(sanitized_content)
        email = db.emails.insert_one({
            'content': sanitized_content,
            'phishingDetected': email_analyzer.detect_phishing(sanitized_content),
            'spamDetected': email_analyzer.detect_spam(sanitized_content),
            'lexicalDiversity': email_analyzer.lexical_diversity(sanitized_content),
            'grammarIssues': email_analyzer.grammar_checker(sanitized_content),
            'fleschReadingEase': email_analyzer.flesch_reading_ease(sanitized_content),
            'toxicityScore': toxicity_score,
            'spamScore': spam_score,
            'incoherentScore': incoherent_score,
            'riskScore': email_analyzer.calculate_risk_score(sanitized_content),
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

@core.route('/malicious-url')
def maliciousUrl():
    if 'user' not in session:
        return redirect(url_for('auth.login'))
    
    if request.method == 'GET':
        return render_template('Malicious_Link_Page.html')
    
    if request.method == 'POST':
        pass

@core.route('/history')
def history():
    if 'user' not in session:
        return redirect(url_for('auth.login'))
    
    if request.method == 'GET':
        return render_template('History_Page.html')
    
    if request.method == 'POST':
        pass









# Mail CRUD
@core.get('/api/mails')
def get_mails():
    if 'user' not in session:
        return {'message': 'Unauthorized'}
    
    else:
        email = session['user']['userinfo']['email']
        user = db.users.find_one({'email': email})

        filter = {'owner': user['_id']}
        mails = list(db.mails.find(filter))

        response = Response(
            response=dumps(mails),
            status=200,
            mimetype='application/json'
        )

        return response

@core.post('/api/mails')
def add_mail():
    if 'user' not in session:
        return {'message': 'Unauthorized'}
    
    else:
        email = session['user']['userinfo']['email']
        user = db.users.find_one({'email': email})

        _json = request.json
        _json['owner'] = ObjectId(user['_id'])
        db.mails.insert_one(_json)

        resp = jsonify({'message': 'Mail added successfully'})
        resp.status_code = 200
        return resp

# @core.patch('/api/mails/<id>')
# def update_mail(id):
#     _json = request.json
#     # _json['owner'] = ObjectId(_json['owner'])
#     db.mails.update_one({'_id': ObjectId(id)}, {"$set": _json})

#     resp = jsonify({'message': 'Mail updated successfully'})
#     resp.status_code = 200
#     return resp

@core.delete('/api/mails/<id>')
def delete_mail(id):
    if 'user' not in session:
        return {'message': 'Unauthorized'}
    
    else:
        email = session['user']['userinfo']['email']
        user = db.users.find_one({'email': email})

        mail = db.mails.find_one({'_id': ObjectId(id)})
        if mail is None or mail['owner'] != user['_id']:
            return {'message': 'Unauthorized'}
        
        else:
            db.mails.delete_one({'_id': ObjectId(id)})
            resp = jsonify({'message': 'Mail deleted successfully'})
            resp.status_code = 200
            return resp

# URLs CRUD
@core.post('/api/urls')
def add_url():
    _json = request.json
    _json['mail'] = ObjectId(_json['mail'])
    db.urls.insert_one(_json)

    resp = jsonify({'message': 'URL added successfully'})
    resp.status_code = 200
    return resp