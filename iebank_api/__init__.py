from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from datetime import timedelta
import os
from dotenv import load_dotenv
import os
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
CORS(app, supports_credentials=True)
load_dotenv()  
# Configure secrets
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-secret-key')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'fallback-jwt-secret-key')
app.permanent_session_lifetime = timedelta(days=1)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)


bcrypt = Bcrypt(app)
jwt = JWTManager(app)


'''if os.getenv('ENV') == 'production':
    CORS(app, supports_credentials=True, resources={r"/*": {"origins": "http://localhost:8080"}})
else:
    CORS(app, supports_credentials=True, resources={
        r"/*": {
            "origins": "http://localhost:8080",
            "allow_headers": ["Content-Type", "Authorization", "x-access-token"],
            "expose_headers": ["Access-Control-Allow-Origin"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
        }
    })'''
    
   

# Select environment based on the ENV environment variable
if os.getenv('ENV') == 'local':
    print("Running in local mode")
    app.config.from_object('config.LocalConfig')
elif os.getenv('ENV') == 'dev':
    print("Running in development mode")
    app.config.from_object('config.DevelopmentConfig')
elif os.getenv('ENV') == 'ghci':
    print("Running in github mode")
    app.config.from_object('config.GithubCIConfig')
elif os.getenv('ENV') == 'uat':
    print("Running in github mode")
    app.config.from_object('config.UATConfig')

# Default SQLite database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///local.db')

db = SQLAlchemy(app)
CORS(app)
migrate = Migrate(app, db)

# Create database tables
with app.app_context():
   db.create_all()

# Import routes and models
from iebank_api.models import User
from iebank_api import routes

# Debugging URL Map
print(app.url_map)
print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")

def create_admin_user():
    with app.app_context():
        # Define the admin user details
        username = 'adminuser'
        password_hash = 'adminpassword'
        email = 'adminuser@example.com'
        date_of_birth = '2004-02-28'
        admin = True

        # Hash the password
        hashed_password = generate_password_hash(password_hash, method='pbkdf2:sha256')

        # Convert date_of_birth to a datetime object
        date_of_birth = datetime.strptime(date_of_birth, '%Y-%m-%d')

        # Create the new admin user
        new_user = User(
            username=username,
            password_hash=hashed_password,
            email=email,
            date_of_birth=date_of_birth,
            admin=admin
        )

        # Add the new user to the database
        # if the new user does not already exist
        if User.query.filter_by(username=username).first():
            print(f"Admin user '{username}' already exists.")
            return
        
        db.session.add(new_user)
        db.session.commit()

        print(f"Admin user '{username}' created successfully.")

create_admin_user()