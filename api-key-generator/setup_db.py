from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os
from sqlalchemy import create_engine
from sqlalchemy_utils import database_exists, create_database

load_dotenv()

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    api_keys = db.relationship('APIKey', backref='user', lazy=True)

class APIKey(db.Model):
    __tablename__ = 'api_keys'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(32), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

if __name__ == '__main__':
    # Get database URL from .env
    database_url = os.getenv('DATABASE_URL')
    
    # Create engine and database if it doesn't exist
    engine = create_engine(database_url)
    if not database_exists(engine.url):
        create_database(engine.url)
        print("Database created successfully!")
    
    # Create all tables
    db.metadata.create_all(engine)
    print("Tables created successfully!")
    print("Database tables created successfully!")
