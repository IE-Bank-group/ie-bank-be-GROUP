from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt

import os
key = os.urandom(24)
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = key


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

db = SQLAlchemy(app)
CORS(app)
login_manager = LoginManager(app)
migrate = Migrate(app, db)

login_manager.login_view = 'accounts.login'

from iebank_api.models import User  # Import after initializing db to avoid circular imports

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter(User.id == int(user_id)).first # Fetch user from the database by ID

# Create database tables
with app.app_context():
    db.create_all()

# Import routes after the app is fully configured
from iebank_api import routes

# Print URL map for debugging
print(app.url_map)
