from flask import Flask, request, jsonify
from iebank_api import db, app
from flask_httpauth import HTTPBasicAuth
from iebank_api.models import Account, User, Transaction
from werkzeug.security import generate_password_hash, check_password_hash
from flask import abort
from flask_login import login_user, login_required, logout_user, current_user
from functools import wraps
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import jwt


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

@app.route('/register', methods=['POST'])
def register():
    # Route to register a new user
    data = request.get_json()
    required_fields = ['username', 'password']
    if not data or not all(field in data for field in required_fields):
        abort(400)
        
    existing_user = User.query.filter_by(username=data['username']).first()
    if existing_user:
        return jsonify({'error': 'User already exists'}), 400

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')

    new_user = User(
        username=data['username'],
        password=hashed_password,
    )

    db.session.add(new_user)
    db.session.commit()

    return format_user(new_user)


@app.route('/login', methods=['POST'])
def login():
   try:
       data = request.get_json()
       required_fields = ['username', 'password']
       if not data or not all(field in data for field in required_fields):
           abort(400) 


       user = User.query.filter_by(username=data['username']).first()
       if not user:
           abort(401) 


       if check_password_hash(user.password, data['password']):
           # Generate token
           token = jwt.encode({
               'user_id': user.id,
               'exp': datetime.utcnow() + timedelta(hours=24)
           }, app.config['SECRET_KEY'], algorithm='HS256')


           return jsonify({
               'message': 'Login successful',
               'token': token,
               'user': {
                   'id': user.id,
                   'username': user.username,
                   'admin': user.admin,
               }
           }), 200
       else:
           abort(401) 
   except Exception as e:
       print(f"Error during login: {e}")
       abort(500) 

        
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')  
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            # Decode the token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(id=data['user_id']).first()

            if not current_user:
                return jsonify({'message': 'User not found!'}), 401

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        except Exception as e:
            print(f"Error decoding token: {e}")
            return jsonify({'message': 'An error occurred during token validation.'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user_portal', methods=['GET'])
@token_required
def user_portal(current_user):
    # Route to display the user portal with their accounts and transactions
    accounts = Account.query.filter_by(user_id=current_user.id).all()
    transactions = Transaction.query.join(Account, Transaction.from_account_id == Account.id).filter(Account.user_id == current_user.id).all()

    return {
        'user': format_user(current_user),
        'accounts': [format_account(account) for account in accounts],
        'transactions': [format_transaction(transaction) for transaction in transactions]
    }
    
@app.route('/admin_portal', methods=['GET'])
@token_required
def admin_portal(current_user):
    # Route to display the admin portal with all users
    if current_user.admin != True:
        abort(401)  

    users = User.query.all()
    return {
        'users': [format_user(user) for user in users]
    }

@app.route('/accounts', methods=['POST'])
@token_required
def create_account(current_user):
  
    data = request.get_json()
    required = ['name', 'currency', 'balance', 'country']
    if not data or not all(field in data for field in required):
        abort(400)  

    name = data['name']
    currency = data['currency']
    balance = data['balance']
    country = data['country']

    account = Account(name=name, currency=currency, balance=balance, country=country, user_id=current_user.id)
    db.session.add(account)
    db.session.commit()
    return format_account(account)

@app.route('/accounts', methods=['GET'])
@token_required
def get_accounts(current_user):
    # Route to get all accounts for the logged-in user
    accounts = Account.query.filter_by(user_id=current_user.id).all()
    return {'accounts': [format_account(account) for account in accounts]}

@app.route('/accounts/<int:id>', methods=['GET'])
@token_required
def get_account(current_user, id):
    # Route to get a specific account by ID
    account = Account.query.get(id)
    if not account or account.user_id != current_user.id:
        abort(500)
    return format_account(account)

@app.route('/accounts/<int:id>', methods=['PUT'])
@token_required
def update_account(current_user, id):
    # Route to update a specific account by ID
    account = Account.query.get(id)
    if not account or account.user_id != current_user.id:
        abort(500)
    account.name = request.json['name']
    db.session.commit()
    return format_account(account)

@app.route('/accounts/<int:id>', methods=['DELETE'])
@token_required
def delete_account(current_user, id):
    # Route to delete a specific account by ID
    account = Account.query.get(id)
    if not account or account.user_id != current_user.id:
        abort(500)
    db.session.delete(account)
    db.session.commit()
    return format_account(account)

@app.route('/transactions', methods=['POST'])
@token_required
def transfer_money(current_user):
    data = request.get_json()
    app.logger.info(f"Received data: {data}")

    # Validate required fields
    required_fields = ['from_account_number', 'to_account_number', 'amount']
    if not data or not all(field in data for field in required_fields):
        app.logger.error("Missing required fields")
        return jsonify({'message': 'Missing required fields'}), 400

    from_account_number = data['from_account_number']
    to_account_number = data['to_account_number']
    amount = data['amount']

    # Validate that accounts exist and belong to the current user (for the source account)
    from_account = Account.query.filter_by(account_number=from_account_number).first()
    to_account = Account.query.filter_by(account_number=to_account_number).first()

    if not from_account or from_account.user_id != current_user.id or not to_account:
        app.logger.error("Invalid account details")
        return jsonify({'message': 'Invalid account details'}), 400

    # Validate sufficient funds
    if from_account.balance < amount:
        app.logger.error("Insufficient funds")
        return jsonify({'message': 'Insufficient funds!'}), 400

    # Update account balances
    from_account.balance -= amount
    to_account.balance += amount

    # Create the transaction
    transaction = Transaction(
        from_account_id=from_account.id,
        to_account_id=to_account.id,
        amount=amount
    )
    db.session.add(transaction)
    db.session.commit()

    app.logger.info("Transaction successful")
    return jsonify({
        'transaction': {
            'id': transaction.id,
            'from_account_id': transaction.from_account_id,
            'to_account_id': transaction.to_account_id,
            'amount': transaction.amount,
        },
        'message': 'Transaction successful!'
    }), 200

@app.route('/transactions', methods=['GET'])
@token_required
def get_transactions(current_user):
    # Route to get all transactions for the logged-in user
    transactions = Transaction.query.join(Account, Transaction.from_account_id == Account.id).filter(Account.user_id == current_user.id).all()
    return {'transactions': [format_transaction(transaction) for transaction in transactions]}


@app.route('/admin/users', methods=['POST'])
@token_required
def create_user(current_user):
    # Route for admin to create a new user
    if current_user.admin != True:
        abort(401)  # Unauthorized

    data = request.get_json()
    required_fields = ['username', 'password']
    if not data or not all(field in data for field in required_fields):
        abort(500)

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(
        username=data['username'],
        password=hashed_password,
        admin=data['admin'],
    )

    db.session.add(new_user)
    db.session.commit()

    return format_user(new_user)

@app.route('/admin/users/<int:id>', methods=['PUT'])
@token_required
def update_user(current_user, id):
    # Route for admin to update a user by ID
    if current_user.admin != True:
        abort(401)  # Unauthorized

    user = User.query.get(id)
    if not user:
        abort(500)
    user.username = request.json['username']
    user.password = generate_password_hash(request.json['password'], method='pbkdf2:sha256')
    user.admin = request.json['admin']
    db.session.commit()
    return format_user(user)

@app.route('/admin/users/<int:id>', methods=['DELETE'])
@token_required
def delete_user(current_user, id):
    # Route for admin to delete a user by ID
    if current_user.admin != True:
        abort(401)  # Unauthorized

    user = User.query.get(id)
    if not user:
        abort(500)
    db.session.delete(user)
    db.session.commit()
    return format_user(user)

@app.route('/create_admin', methods=['POST'])
@token_required
def create_admin():
    # Route to create an admin user
    data = request.get_json()
    required_fields = ['username', 'password']
    if not data or not all(field in data for field in required_fields):
        abort(500)

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(
        username=data['username'],
        password=hashed_password,
        admin=True,
    )

    db.session.add(new_user)
    db.session.commit()

    return format_user(new_user)
    
def format_transaction(transaction):
    return {
        'id': transaction.id,
        'amount': transaction.amount,
        'currency': transaction.from_account.currency,
        'from_account': transaction.from_account.account_number,
        'to_account': transaction.to_account.account_number
    }
    
def format_user(user):
    return {
        'id': user.id,
        'username': user.username,
        'password': user.password,
        'admin': user.admin
    }
    
def format_account(account):
    return {
        'id': account.id,
        'name': account.name,
        'country': account.country,
        'account_number': account.account_number,
        'balance': account.balance,
        'currency': account.currency,
        'status': account.status,
    }