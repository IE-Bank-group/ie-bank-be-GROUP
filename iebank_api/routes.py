from flask import Flask, request, jsonify
from iebank_api import db, app
from flask_httpauth import HTTPBasicAuth
from iebank_api.models import Account, User
from werkzeug.security import generate_password_hash, check_password_hash
from flask import abort
from flask_login import login_user, login_required, logout_user, current_user
from functools import wraps
from iebank_api.forms import RegisterForm, LoginForm
import string
import random

auth = HTTPBasicAuth()

@app.route('/')
def hello_world():
    return 'Hello, World!'

@app.route('/skull', methods=['GET'])
def skull():
    text = 'Hi! This is the BACKEND SKULL! 💀 '
    
    text = text +'<br/>Database URL:' + db.engine.url.database
    if db.engine.url.host:
        text = text +'<br/>Database host:' + db.engine.url.host
    if db.engine.url.port:
        text = text +'<br/>Database port:' + db.engine.url.port
    if db.engine.url.username:
        text = text +'<br/>Database user:' + db.engine.url.username
    if db.engine.url.password:
        text = text +'<br/>Database password:' + db.engine.url.password
    return text

@app.route('/accounts', methods=['POST'])
@auth.login_required
def create_account():
    user = auth.current_user()
    data = request.json
    if not data or 'name' not in data or 'currency' not in data or 'country' not in  data:
        return jsonify({'error': 'Missing account information'}), 400
    
    new_account = Account(
        name=data['name'],
        account_number=''.join(random.choices(string.digits, k=20)),
        balance=0.0,
        currency=data['currency'],
        status='Active',
        country=data['country'],
        user_id=user.id
    )
    db.session.add(new_account)
    db.session.commit()
    return jsonify({'message': 'Account created succesfully', 'account': format_account(new_account)}), 201

@app.route('/accounts', methods=['GET'])
@auth.login_required
def get_accounts():
    user = auth.current_user()
    accounts = Account.query.filter_by(user_id=user.id).all()
    return jsonify([format_account(account) for account in accounts])

@app.route('/accounts/<int:id>', methods=['GET'])
@auth.login_required
def get_account(id):
    user = auth.current_user()
    account = Account.query.filter_by(id=id, user_id=user.id).first_or_404()
    return jsonify(format_account(account))

@app.route('/accounts/<int:id>', methods=['PUT'])
@auth.login_required
def update_account(id):
    user = auth.current_user()
    account = Account.query.filter_by(id=id, user_id=user.id).first_or_404()
    data = request.json

    if 'name' in data:
        account.name = data['name']
    if 'currency' in data:
        account.currency = data['currency']
    if 'country' in data:
        account.country = data['country']
    if 'status' in data:
        account.status = data['status']

    db.session.commit()
    return jsonify({'message': 'Account updated successfully', 'account': format_account(account)})

@app.route('/accounts/<int:id>', methods=['DELETE'])
@auth.login_required
def delete_account(id):
    user = auth.current_user()
    account = Account.query.filter_by(id=id, user_id=user.id).first_or_404()
    db.session.delete(account)
    db.session.commit()
    return jsonify({'message': 'Account deleted successfully'})

def format_account(account):
    return {
        'id': account.id,
        'name': account.name,
        'country': account.country,
        'account_number': account.account_number,
        'balance': account.balance,
        'currency': account.currency,
        'status': account.status,
        'created_at': account.created_at
    }
    
# ------ User routes ---------

@auth.verify_password
def verify_password(username, password):
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
      return user
    return None  


def admin_required(func):
    @wraps(func)
    @auth.login_required
    def wrapper(*args, **kwargs):
        user = auth.current_user()
        # Check if the user is authenticated
        if not user:
            abort(401, description="Authentication required")

        # Check if the user is an admin
        if not getattr(user, 'admin', False):
            abort(403, description="Admin access required")

        return func(*args, **kwargs)
    return wrapper

# Get all users
@app.route('/users', methods=['GET'])
@admin_required
def get_users():
    users = User.query.all()
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'admin': user.admin
    } for user in users])

# Create a new user
@app.route('/users', methods=['POST'])
@admin_required
def create_user():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Missing username or password'}), 400
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'User already exists'}), 400
    
    admin = data.get('admin', False)
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(username=data['username'], password_hash=hashed_password, admin=admin)
    db.session.add(new_user)
    db.session.commit()
    
    # Create associated account for the new user
    new_account = Account(
        name=f"{data['username']}'s Account",
        account_number=''.join(random.choices(string.digits, k=20)),
        balance=0.0,
        currency='EUR',
        status='Active',
        country='Spain',
        user_id=new_user.id
    )
    db.session.add(new_account)
    db.session.commit()
    
    return jsonify({'message': 'User created successfully'}), 201

# Update an existing user
@app.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    data = request.json

    if 'username' in data:
        user.username = data['username']
    if 'password' in data:
        user.password = generate_password_hash(data['password'], method='sha256')

    db.session.commit()
    return jsonify({'message': 'User updated successfully'})

# Delete a user
@app.route('/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'})

def format_user(user):
    return {
        'id': user.id,
        'username': user.username,
        'password_hash': user.password_hash,
        'admin': user.admin
    }

# Ensure admin exists with ID 1
@app.route('/ensure_admin', methods=['POST'])
def ensure_admin_user():
    # Check if a user with ID 1 exists
    admin_user = User.query.get(1)
    
    if admin_user:
        if admin_user.admin:
            return jsonify({'message': 'Admin user with ID 1 already exists'}), 200
        else:
            return jsonify({'error': 'User with ID 1 exists but is not an admin'}), 400
    
    # Create an admin user with ID 1
    admin_user = User(
        id=1,  # Explicitly set ID to 1
        username='admin',
        password_hash=generate_password_hash('adminpassword', method='sha256'),
        admin=True
    )
    db.session.add(admin_user)
    db.session.commit()
    return jsonify({'message': 'Admin user with ID 1 created successfully'}), 201

# ------ Register Forms --------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return jsonify({"message": "You are already registered.", "status": "info"}), 400
    
    data = request.json
    if not data:
        return jsonify({"error": "Invalid request. Please provide JSON data."}), 400

     # Use RegisterForm for validation
    form = RegisterForm(data=data)
    if not form.validate():
        # Return all validation errors in the response
        errors = {
            field: error[0] for field, error in form.errors.items()
        }
        return jsonify({"message": "Validation errors occurred.", "errors": errors}), 400

    # Create a new user
    hashed_password = generate_password_hash(form.password.data)
    user = User(username=form.username.data, password_hash=hashed_password)
    db.session.add(user)
    db.session.commit()

    # Log the user in
    login_user(user)

    return jsonify({"message": "User registered and logged in successfully.", "status": "success", "username": user.username}), 201

@app.route('/loginuser', methods=['POST'])
def loginuser():
    if current_user.is_authenticated:
        return jsonify({"message": "You are already logged in.", "status": "info"}), 400

    # Get JSON data from the request
    data = request.json
    if not data:
        return jsonify({"error": "Invalid request. Please provide JSON data."}), 400

    # Use LoginForm for validation
    form = LoginForm(data=data)
    if not form.validate():
        errors = {
            field: error[0] for field, error in form.errors.items()
        }
        return jsonify({"message": "Validation errors occurred.", "errors": errors}), 400

    # Authenticate the user
    user = User.query.filter_by(username=form.username.data).first()
    if user and check_password_hash(user.password_hash, form.password.data):
        login_user(user)
        return jsonify({ "message": "Logged in successfully.",
            "status": "success",
            "username": user.username,
            "admin": user.admin}), 200
    else:
        return jsonify({"error": "Invalid username or password."}), 401
    
@app.route("/logout", methods=["POST"])
@login_required
def logout():
    if not current_user.is_authenticated:
        return jsonify({"error": "You are not logged in."}), 400

    logout_user()
    return jsonify({"message": "You have been logged out successfully.", "status": "success"}), 200

# ----- Money Transfer Routes ------------

@app.route('/transfer', methods=['POST'])
@auth.login_required
def tranfer_money():
    user = auth.current_user()
    data = request.json
    if not data or 'from_account' not in data or 'to_account' not in data or 'amount' not in data:
        return jsonify({'error': 'Missing transfer information'})
    
    from_account = Account.query.filter_by(account_number=data['from_account'], user_id=user>id).first()
    to_account = Account.query.filter_by(account_number=data['to_account']).first()
    
    if not from_account:
        return jsonify({'error': 'Sender account not found or not owned by user'}), 404
    if not to_account:
        return jsonify({'error': 'Recipient account not found'}), 404
    if from_account.balance < data['amount']:
        return jsonify({'error': 'Insufficient funds'}), 400

    # Perform the transfer
    from_account.balance -= data['amount']
    to_account.balance += data['amount']

    db.session.commit()
    return jsonify({'message': 'Transfer successful'}), 200

# ------ Admin Routes (funds) ----------

@app.route('/add_funds', methods=['POST'])
@auth.login_required
@admin_required
def add_funds():
    data = request.json
    if not data or 'account_number' not in data or 'amount' not in data:
        return jsonify({'error': 'Missing account information'}), 400

    account = Account.query.filter_by(account_number=data['account_number']).first()
    if not account:
        return jsonify({'error': 'Account not found'}), 404

    # Add funds to the account
    account.balance += data['amount']
    db.session.commit()
    return jsonify({'message': 'Funds added successfully', 'account': format_account(account)}), 200

