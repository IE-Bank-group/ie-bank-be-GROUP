from iebank_api import db
from datetime import datetime
import string, random
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), nullable=False)
    account_number = db.Column(db.String(20), nullable=False, unique=True)
    balance = db.Column(db.Float, nullable=False, default=0.0)
    currency = db.Column(db.String(1), nullable=False, default="€")
    status = db.Column(db.String(10), nullable=False, default="Active")
    country = db.Column(db.String(15), nullable=False, default="No Country Selected")
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def __repr__(self):
        return '<Account %r>' % self.account_number

    def __init__(self, name, balance, currency, country, user_id):
        self.name = name
        self.account_number = ''.join(random.choices(string.digits, k=20))
        self.balance = balance
        self.currency = currency
        self.status = "Active"
        self.country = country
        self.user_id = user_id

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    accounts = db.relationship('Account', backref='user', lazy=True)

    def __repr__(self):
        return f'{self.username}'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False) # Assuming currency codes like USD, EUR, etc.
    from_account_id = db.Column(db.Integer, db.ForeignKey('account.id'), nullable=False)
    to_account_id = db.Column(db.Integer, db.ForeignKey('account.id'), nullable=False)
    from_account = db.relationship('Account', foreign_keys=[from_account_id], backref='outgoing_transactions')
    to_account = db.relationship('Account', foreign_keys=[to_account_id], backref='incoming_transactions')

    def __repr__(self):
        return f'<Transaction {self.id}>'

    def __init__(self, amount, from_account_id, to_account_id):
        self.amount = amount
        self.from_account_id = from_account_id
        self.to_account_id = to_account_id

    