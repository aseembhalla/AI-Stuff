from flask import Flask, render_template, jsonify, request, redirect, url_for, session
from flask_login import LoginManager, login_required, current_user
from flask_oauthlib.client import OAuth
from models import db, User, APIKey
from api_generator import generate_api_key
from config import Config
from auth import google, login, authorized, get_google_oauth_token

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

oauth = OAuth(app)

# Register OAuth routes
app.route('/login')(login)
app.route('/login/authorized')(authorized)

# Token getter for OAuth
@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/generate', methods=['POST'])
@login_required
def generate_key():
    data = request.json
    key_name = data.get('name')
    
    if not key_name:
        return jsonify({'error': 'Key name is required'}), 400
    
    # Check if key name already exists for this user
    existing_key = APIKey.query.filter_by(name=key_name, user_id=current_user.id).first()
    if existing_key:
        return jsonify({'error': 'Key name already exists'}), 400
    
    api_key = generate_api_key()
    new_key = APIKey(key=api_key, name=key_name, user_id=current_user.id)
    db.session.add(new_key)
    db.session.commit()
    return jsonify({'api_key': api_key, 'name': key_name})

@app.route('/dashboard')
@login_required
def dashboard():
    api_keys = APIKey.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', api_keys=api_keys)

@app.route('/api/keys')
@login_required
def get_keys():
    api_keys = APIKey.query.filter_by(user_id=current_user.id).all()
    return jsonify([
        {
            'id': key.id,
            'name': key.name,
            'key': key.key,
            'created_at': key.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        for key in api_keys
    ])

@app.route('/api/key/<int:key_id>')
@login_required
def get_key(key_id):
    key = APIKey.query.filter_by(id=key_id, user_id=current_user.id).first_or_404()
    return jsonify({
        'name': key.name,
        'key': key.key
    })

@app.route('/logout')
@login_required
def logout():
    from flask_login import logout_user
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
