from flask import request, redirect, url_for, session
from flask_login import login_user, login_required, current_user
from flask_oauthlib.client import OAuth
from dotenv import load_dotenv
import os
from models import User, db

load_dotenv()

oauth = OAuth()

google = oauth.remote_app(
    'google',
    consumer_key=os.getenv('GOOGLE_CLIENT_ID'),
    consumer_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    request_token_params={
        'scope': 'email'
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth'
)

def get_google_oauth_token():
    return session.get('google_token')

# Routes
def login():
    return google.authorize(callback='http://localhost:5000/login/authorized')

def authorized():
    resp = google.authorized_response()
    if resp is None or resp.get('access_token') is None:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )
    
    session['google_token'] = (resp['access_token'], '')
    me = google.get('userinfo')
    user_info = me.data
    
    # Handle cases where name might not be available
    name = user_info.get('name', f"User {user_info.get('email', 'Unknown')}".split('@')[0])
    
    user = User.query.filter_by(google_id=user_info['id']).first()
    if not user:
        user = User(
            google_id=user_info['id'],
            email=user_info['email'],
            name=name
        )
        db.session.add(user)
        db.session.commit()
    
    login_user(user)
    return redirect(url_for('dashboard'))

def dashboard():
    return render_template('dashboard.html')
