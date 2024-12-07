from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from datetime import datetime, timedelta
import secrets
import os

#secret_key = secrets.token_hex(32)
#key = os.urandom(24)

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.permanent_session_lifetime = timedelta(days=1)  # session lifetime for tokens

bcrypt = Bcrypt(app)
jwt = JWTManager(app)


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

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db = SQLAlchemy(app)
CORS(app)
migrate = Migrate(app, db)

from iebank_api.models import User  # Import after initializing db to avoid circular imports

# Create database tables
with app.app_context():
   db.create_all()

# Import routes after the app is fully configured
from iebank_api import routes

# Print URL map for debugging
print(app.url_map)