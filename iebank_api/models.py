from iebank_api import db
from datetime import datetime
import string, random
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), nullable=False)
    account_number = db.Column(db.String(20), nullable=False, unique=True)
    balance = db.Column(db.Float, nullable=False, default = 0.0)
    currency = db.Column(db.String(1), nullable=False, default="€")
    status = db.Column(db.String(10), nullable=False, default="Active")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    country = db.Column(db.String(15), nullable=False, default="No Country Selected")
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def __repr__(self):
        return '<Event %r>' % self.account_number

    def __init__(self, name, account_number, currency, balance, status, country, user_id):
        self.name = name
        self.account_number = ''.join(random.choices(string.digits, k=20))
        self.currency = currency
        self.balance = 0.0
        self.status = "Active"
        self.country = country
        self.user_id = user_id
        
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False) # user or admin
    accounts = db.relationship('Account', backref='user', lazy=True)
    
    def __repr__(self):
        return f'{self.username}'
    
    def __init__(self, username, password_hash, admin=False):
        self.username = username
        self.password_hash = password_hash
        self.admin = admin
        
            
    ''''@property
    def password(self):
        raise AttributeError('Password field is not readable')
    
    @password.setter
    def password(self, password_hash: str):
        self.password_hash = generate_password_hash(password_hash)
        
    def check_password(self, password_hash: str):
        return check_password_hash(self.password_hash, password_hash)
    
def create_default_admin():
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin = User(
            username = 'admin',
            password=generate_password_hash('password123', method='sha256'),
            role = 'admin'
        )
        db.session.add(admin)
        db.session.commit()
        print("Default admin account created: username='admin', password='password123'")
    else:
        print("Admin account already exists.")'''