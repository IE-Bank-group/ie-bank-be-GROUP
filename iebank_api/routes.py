from flask import Flask, request, jsonify, abort
from iebank_api import db, app
from iebank_api.models import Account, User, Transaction
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)
from datetime import datetime, timedelta

# JWT Initialization
jwt = JWTManager(app)


@app.route('/')
def hello_world():
    return 'Hello, World!'


@app.route('/skull', methods=['GET'])
def skull():
    text = 'Hi! This is the BACKEND SKULL! 💀 '

    # Add database connection info to the response for debugging
    text += f'<br/>Database URL: {db.engine.url.database}'
    if db.engine.url.host:
        text += f'<br/>Database host: {db.engine.url.host}'
    if db.engine.url.port:
        text += f'<br/>Database port: {db.engine.url.port}'
    if db.engine.url.username:
        text += f'<br/>Database user: {db.engine.url.username}'
    if db.engine.url.password:
        text += f'<br/>Database password: {db.engine.url.password}'
    return text


@app.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    required_fields = ['username', 'password', 'email', 'date_of_birth']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400

    try:
        date_of_birth = datetime.strptime(data['date_of_birth'], '%Y-%m-%d')
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400

    # Ensure user is at least 18 years old
    if (datetime.utcnow() - date_of_birth).days < 18 * 365:
        return jsonify({'error': 'Must be at least 18 years old to register'}), 400

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(
        username=data['username'],
        email=data['email'],
        password_hash=hashed_password,
        date_of_birth=date_of_birth
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully', 'user': format_user(new_user)}), 201


@app.route('/login', methods=['POST'])
def login():
    # Actual login logic
    data = request.get_json()
    required_fields = ['username', 'password']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    user = User.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify({'error': 'Invalid username or password'}), 401

    # Generate access token
    token = create_access_token(identity=user.id, additional_claims={"admin": user.admin})
    redirect_url = '/admin_portal' if user.admin else '/user_portal'
    response = jsonify({
        'message': 'Login successful',
        'token': token,
        'user': {
            'id': user.id,
            'username': user.username,
            'admin': user.admin
        },
        'redirect_url': redirect_url
    })        
    return response, 200



@app.route('/user_portal', methods=['GET'])
@jwt_required()
def user_portal():
    """Display user portal with accounts and transactions"""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    accounts = Account.query.filter_by(user_id=current_user.id).all()
    transactions = Transaction.query.join(Account, Transaction.from_account_id == Account.id).filter(Account.user_id == current_user.id).all()

    return jsonify({
        'user': format_user(current_user),
        'accounts': [format_account(account) for account in accounts],
        'transactions': [format_transaction(transaction) for transaction in transactions]
    }), 200

'''@app.route('/create_admin', methods=['POST'])
@jwt_required()
def create_admin():
    data = request.get_json()
    required_fields = ['username', 'password', 'email', 'date_of_birth']
    if not data or not all(field in data for field in required_fields):
        return jsonify({"message": "Missing required fields"}), 400

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    try:
        date_of_birth = datetime.strptime(data['date_of_birth'], '%Y-%m-%d')
    except ValueError:
        return jsonify({"message": "Invalid date format. Use YYYY-MM-DD"}), 400

    new_admin = User(
        username=data['username'],
        email=data['email'],
        password_hash=hashed_password,
        date_of_birth=date_of_birth,
        admin=True,
    )
    db.session.add(new_admin)
    db.session.commit()

    return jsonify({
        "id": new_admin.id,
        "username": new_admin.username,
        "email": new_admin.email,
        "admin": new_admin.admin,
    }), 201'''


@app.route('/admin_portal', methods=['GET'])
@jwt_required()
def admin_portal():
    """Admin portal to view all users"""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    # Check if the user is an admin
    if not current_user or not current_user.admin:
        return jsonify({'error': 'Unauthorized access'}), 403

    # Fetch all users
    users = User.query.all()

    # Format user details for response
    formatted_users = [format_user(user) for user in users]
    
    return jsonify({'users': formatted_users}), 200

@app.route('/admin/users', methods=['POST'])
@jwt_required()
def create_user():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    # Route for admin to create a new user
    if not current_user or not current_user.admin:
        return jsonify({'error': 'Unauthorized access'}), 401

    data = request.get_json()
    required_fields = ['username', 'email', 'password', 'date_of_birth', 'admin']
    if not data or not all(field in data for field in required_fields):
        abort(500)

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')

    # Convert date_of_birth to a datetime object
    date_of_birth = datetime.strptime(data['date_of_birth'], '%Y-%m-%d')

    new_user = User(
        username=data['username'],
        email=data['email'],
        password_hash=hashed_password,
        date_of_birth=date_of_birth,
        admin=data['admin']
    )

    db.session.add(new_user)
    db.session.commit()

    return format_user(new_user)

@app.route('/admin/users/<int:id>', methods=['PUT'])
@jwt_required()
def update_user(id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    # Route for admin to update a user by ID
    if not current_user or not current_user.admin:
        return jsonify({'error': 'Unauthorized access'}), 401

    user = User.query.get(id)
    if not user:
        abort(500)

    user.username = request.json['username']
    user.email = request.json['email']
    if 'password' in request.json and request.json['password']:
        user.password = generate_password_hash(request.json['password'], method='pbkdf2:sha256')
    user.date_of_birth = datetime.strptime(request.json['date_of_birth'], '%Y-%m-%d')
    user.admin = request.json['admin']
    db.session.commit()

@app.route('/admin/users/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_user(id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    # Check if the current user is an admin
    if not current_user or not current_user.admin:
        return jsonify({'error': 'Unauthorized access'}), 401

    # Find the user to delete
    user_to_delete = User.query.get(id)
    if not user_to_delete:
        return jsonify({'error': 'User not found'}), 404

    try:
        # Delete the user
        db.session.delete(user_to_delete)
        db.session.commit()
        return jsonify({'message': f'User with ID {id} has been successfully deleted.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete user', 'details': str(e)}), 500


@app.route('/accounts/<account_number>/', methods=['PUT'])
@jwt_required()
def update_account(account_number):
    current_user = get_jwt_identity()
    
    current_user_account = Account.query.filter_by(user_id=current_user.get("id")).first()
    
    if not current_user.admin or (current_user_account and current_user.get("id") == current_user_account.user_id):
        return jsonify({"msg": "Admin access required"}), 403

    try:
        
        account = Account.query.filter_by(account_number=account_number).first()
        
        if not account:
            return jsonify({"msg": "Account not found"}), 404

        account.name = request.json.get('name', account.name)
        account.currency = request.json.get('currency', account.currency)
        account.country = request.json.get('country', account.country)
        account.status = request.json.get('status', account.status)

        db.session.commit()
        return jsonify({"msg": "Account updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": "An error occurred"}), 500

@app.route('/accounts/<account_number>/', methods=['DELETE'])
@jwt_required()
def delete_account(account_number):
    current_user = get_jwt_identity()
    if not current_user.admin:
        return jsonify({"msg": "Admin access required"}), 403

    try:
        account = Account.query.filter_by(account_number=account_number).first()
        if not account:
            return jsonify({"msg": "Account not found"}), 404

        db.session.delete(account)
        db.session.commit()
        return jsonify({"msg": "Account deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": "An error occurred"}), 500

@app.route('/accounts', methods=['GET'])
@jwt_required()
def accounts():
    user_id = get_jwt_identity()
    accounts = Account.query.filter_by(user_id=user_id).all()
    return jsonify({"accounts": [format_account(account) for account in accounts]}), 200


@app.route('/accounts', methods=['POST'])
@jwt_required()
def create_account():
    data = request.get_json()
    required_fields = ['name', 'balance', 'currency', 'country']
    if not data or not all(field in data for field in required_fields):
        return jsonify({"message": "Missing required fields"}), 400

    account = Account(
        name=data['name'],
        balance=data['balance'],
        currency=data['currency'],
        country=data['country'],
        user_id=get_jwt_identity(),
    )
    db.session.add(account)
    db.session.commit()

    # Include the account details in the response
    return format_account(account), 201


@app.route('/transactions', methods=['POST'])
@jwt_required()
def transfer_money():
    """Handle money transfer between accounts"""
    current_user_id = get_jwt_identity()  # Get the current user's ID from the JWT
    current_user = User.query.get(current_user_id)

    data = request.get_json()
    app.logger.info(f"Received data for transfer: {data}")

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

    if not from_account:
        app.logger.error(f"Source account not found: {from_account_number}")
    if not to_account:
        app.logger.error(f"Destination account not found: {to_account_number}")
    if from_account.user_id != current_user.id:
        app.logger.error(f"Source account does not belong to current user: {current_user.id}")
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

    app.logger.info("Transfer successful")
    return jsonify({
        'transaction': format_transaction(transaction),
        'message': 'Transfer successful!'
    }), 200


# Helper functions
def format_user(user):
    return {
        'id': user.id, 
        'username': user.username, 
        'email': user.email, 
        'date_of_birth': user.date_of_birth,
        'admin': user.admin
    }


def format_account(account):
    return {
        'name': account.name,
        'account_number': account.account_number,
        'balance': account.balance,
        'currency': account.currency,
        'status': account.status,
        'country': account.country,
        'user_id': account.user_id,
    }


def format_transaction(transaction):
    return {
        'id': transaction.id,
        'amount': transaction.amount,
        'from_account': transaction.from_account.account_number,
        'to_account': transaction.to_account.account_number
    }
