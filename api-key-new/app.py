from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_session import Session
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from sqlalchemy import inspect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timezone, timedelta
from authlib.integrations.flask_client import OAuth
import stripe
import os
from dotenv import load_dotenv
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

# Initialize app and load environment variables
load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql+psycopg2://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['GOOGLE_OAUTH2_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_OAUTH2_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')

# Initialize CSRF protection
csrf = CSRFProtect(app)
app.wsgi_app = ProxyFix(app.wsgi_app)

# Configure allowed redirect URIs
REDIRECT_URIS = [
    'http://localhost:5000/auth/authorize',
    'http://127.0.0.1:5000/auth/authorize'
]

# Configure Flask-Session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production

# Initialize session
Session(app)

# Configure email
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS')
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

# Initialize extensions
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db_session.query(User).get(int(user_id))

# Initialize database
engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'], echo=True)
Session = sessionmaker(bind=engine)
db_session = Session()
Base = declarative_base()

stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET')
STRIPE_PRICE_ID = os.getenv('STRIPE_PRICE_ID')

# Models
class User(UserMixin, Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String(120), unique=True, nullable=False)
    google_id = Column(String(100), unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    api_keys = relationship('APIKey', backref='user', lazy=True)

class APIKey(Base):
    __tablename__ = 'api_keys'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    key_name = Column(String(100), nullable=False)
    api_key = Column(String(32), unique=True, nullable=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow)
    expiry_date = Column(DateTime, nullable=False)
    status = Column(String(20), default='active')
    credits = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def use_credit(self, db_session):
        """Use one credit from this API key."""
        if self.credits <= 0:
            raise ValueError("Not enough credits available")
            
        self.credits -= 1
        db_session.commit()
        return self.credits

# Initialize OAuth
oauth = OAuth(app)

# Register Google OAuth
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError:
        return 'Invalid signature', 400

    # Handle the checkout.session.completed event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        
        # Get the key_name from metadata
        key_name = session['metadata'].get('key_name')
        if key_name:
            # Create new API key
            api_key = secrets.token_hex(16)
            new_key = APIKey(
                key_name=key_name,
                api_key=api_key,
                expiry_date=datetime.utcnow() + timedelta(days=30),
                user_id=current_user.id
            )
            db_session.add(new_key)
            db_session.commit()
            
            return jsonify({'status': 'success'}), 200
    return jsonify({'status': 'error'}), 400

@app.route('/success')
@login_required
def success():
    key_name = request.args.get('key_name')
    if key_name:
        # Create new API key
        api_key = secrets.token_hex(16)
        new_key = APIKey(
            key_name=key_name,
            api_key=api_key,
            expiry_date=datetime.utcnow() + timedelta(days=30),
            user_id=current_user.id,
            credits=int(os.getenv('API_KEY_CREDITS', 5000))
        )
        db_session.add(new_key)
        db_session.commit()
        flash('API key created successfully!', 'success')
    return render_template('success.html')

@app.route('/login')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/')
def home():
    return redirect(url_for('index'))

@app.route('/auth/login')
def auth_login():
    try:
        # Generate a nonce and store it in the session
        nonce = secrets.token_urlsafe(32)
        session['google_nonce'] = nonce

        # Use the first available redirect URI
        redirect_uri = REDIRECT_URIS[0]
        
        # Ensure session is properly configured
        if not session.get('google_nonce'):
            session['google_nonce'] = nonce

        return google.authorize_redirect(
            redirect_uri=redirect_uri,
            access_type='offline',
            prompt='select_account',
            nonce=nonce
        )
    except Exception as e:
        flash(f'Error initiating login: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/auth/authorize')
def authorize():
    try:
        # Get the authorization code from the request
        code = request.args.get('code')
        if not code:
            raise ValueError('No authorization code received')

        # Exchange code for token
        token = google.authorize_access_token()
        if not token:
            raise ValueError('No token received')

        # Verify nonce
        nonce = session.pop('google_nonce', None)
        if not nonce:
            raise ValueError('Nonce not found in session')

        # Get user info
        user_info = google.parse_id_token(token, nonce=nonce)
        if not user_info or not user_info.get('email'):
            raise ValueError('No user info received')

        # Save token to session
        session['google_token'] = token

        # Check if user exists, create if not
        user = db_session.query(User).filter_by(email=user_info['email']).first()
        if not user:
            user = User(
                email=user_info['email'],
                google_id=user_info['sub']
            )
            db_session.add(user)
            db_session.commit()
        
        # Login the user
        login_user(user)
        flash('Successfully logged in.', 'success')
        return redirect(url_for('dashboard'))
    
    except Exception as e:
        flash(f'Authentication error: {str(e)}', 'error')
        return redirect(url_for('auth_login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth_login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        key_name = request.form.get('key_name')
        
        # Validate key name
        if not key_name:
            flash('Key name is required', 'error')
            return redirect(url_for('dashboard'))
            
        # Check if key name already exists for this user
        existing_key = db_session.query(APIKey).filter_by(
            key_name=key_name,
            user_id=current_user.id
        ).first()
        
        if existing_key:
            flash('Error: A key with this name already exists. Please choose a different name.', 'error')
            return redirect(url_for('dashboard'))
            
        # Store the key name in session for later use
        session['pending_key_name'] = key_name
        
        # Create Stripe checkout session
        try:
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price': os.getenv('STRIPE_API_KEY_PRICE_ID'),
                    'quantity': 1,
                }],
                mode='payment',
                success_url=url_for('create_api_key', _external=True),
                cancel_url=url_for('dashboard', _external=True),
            )
            
            return redirect(checkout_session.url)
            
        except Exception as e:
            flash(f'Error initializing payment: {str(e)}', 'error')
            return redirect(url_for('dashboard'))
    
    # Get all API keys for this user
    api_keys = db_session.query(APIKey).filter_by(user_id=current_user.id).all()
    
    # Update status of expired keys
    current_time = datetime.now(timezone.utc)
    
    for key in api_keys:
        # Make sure expiry_date is timezone-aware
        expiry_date = key.expiry_date
        if expiry_date.tzinfo is None:
            expiry_date = expiry_date.replace(tzinfo=timezone.utc)
        
        # Add a small buffer to account for timezone differences
        if expiry_date < current_time - timedelta(minutes=1):
            key.status = 'expired'
    db_session.commit()
    
    return render_template('dashboard.html', api_keys=api_keys, datetime=datetime, timezone=timezone)

@app.route('/create-api-key')
@login_required
def create_api_key():
    # Get the pending key name from session
    key_name = session.pop('pending_key_name', None)
    if not key_name:
        flash('No pending key name found. Please try again.', 'error')
        return redirect(url_for('dashboard'))
        
    try:
        # Generate a unique API key
        api_key = secrets.token_hex(16)
        
        # Create new API key record with automatic expiry date and credits
        new_key = APIKey(
            key_name=key_name,
            api_key=api_key,
            user_id=current_user.id,
            expiry_date=datetime.utcnow() + timedelta(days=30),
            credits=int(os.getenv('API_KEY_CREDITS', 5000))
        )
        db_session.add(new_key)
        db_session.commit()
        
        flash('API key created successfully!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash(f'Error creating API key: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/generate-key', methods=['GET', 'POST'])
@login_required
def generate_key():
    if request.method == 'POST':
        key_name = request.form.get('key_name')
        
        # Validate key name
        if not key_name:
            flash('Key name is required', 'error')
            return redirect(url_for('generate_key', key_name=key_name))
            
        # Check if key name already exists for this user
        existing_key = db_session.query(APIKey).filter_by(
            key_name=key_name,
            user_id=current_user.id
        ).first()
        
        if existing_key:
            flash('Error: A key with this name already exists. Please choose a different name.', 'error')
            return redirect(url_for('generate_key', key_name=key_name))
            
        try:
            # Generate a unique API key
            api_key = secrets.token_hex(16)
            
            # Create new API key record with automatic expiry date
            new_key = APIKey(
                key_name=key_name,
                api_key=api_key,
                user_id=current_user.id,
                expiry_date=datetime.utcnow() + timedelta(days=30)
            )
            db_session.add(new_key)
            db_session.commit()
            
            flash('API key created successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash(f'Error creating API key: {str(e)}', 'error')
            return redirect(url_for('generate_key', key_name=key_name))
            
    # Handle GET request or form errors
    key_name = request.args.get('key_name', '')
    return render_template('generate_key.html', key_name=key_name)


@app.route('/use-credit/<int:key_id>', methods=['POST'])
@login_required
def use_credit(key_id):
    try:
        api_key = db_session.query(APIKey).get(key_id)
        if not api_key:
            return jsonify({'success': False, 'error': 'API key not found'}), 404
            
        if api_key.user_id != current_user.id:
            return jsonify({'success': False, 'error': 'Unauthorized access'}), 403
            
        credits = api_key.use_credit(db_session)
        return jsonify({'success': True, 'credits': credits})
        
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/renew/<int:key_id>')
@login_required
def renew_key(key_id):
    key = db_session.query(APIKey).get(key_id)
    if not key:
        flash('API key not found', 'error')
        return redirect(url_for('dashboard'))
    
    if key.user_id != current_user.id:
        flash('You do not have permission to renew this key', 'error')
        return redirect(url_for('dashboard'))
    
    # Store the key ID in session for later use
    session['pending_key_id'] = key_id
    
    # Create Stripe checkout session
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price': os.getenv('STRIPE_API_KEY_PRICE_ID'),
                'quantity': 1,
            }],
            mode='payment',
            success_url=url_for('renew_success', _external=True),
            cancel_url=url_for('dashboard', _external=True),
        )
        
        return redirect(checkout_session.url)
        
    except Exception as e:
        flash(f'Error initializing payment: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/renew-success')
@login_required
def renew_success():
    # Get the key ID from session
    key_id = session.pop('pending_key_id', None)
    if not key_id:
        flash('Invalid key renewal attempt', 'error')
        return redirect(url_for('dashboard'))
    
    # Get the key
    api_key = db_session.query(APIKey).get(key_id)
    if not api_key:
        flash('API key not found', 'error')
        return redirect(url_for('dashboard'))
    
    if api_key.user_id != current_user.id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard'))
        
    # Update the key's expiry date and reset credits
    api_key.expiry_date = datetime.utcnow() + timedelta(days=30)
    api_key.status = 'active'
    api_key.credits = int(os.getenv('API_KEY_CREDITS', 5000))
    db_session.commit()
    

    
    flash('API key renewed successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/payment-failed')
def payment_failed():
    flash('Payment failed. Please try again.', 'error')
    return render_template('payment_failed.html')



def init_db():
    # Create tables if they don't exist
    Base.metadata.create_all(bind=engine)
    
    # Verify tables exist
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    
    if 'users' not in tables or 'api_keys' not in tables:
        print("Database tables created successfully!")
    else:
        print("Database tables already exist")

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
