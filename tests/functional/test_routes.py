from iebank_api import db, app
from iebank_api.models import User, Account
import pytest
from werkzeug.security import generate_password_hash
from flask_jwt_extended import create_access_token
from datetime import datetime

@pytest.fixture
def testing_client():
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            # Create a test user
            test_user = User(username='testuser', email='testuser@example.com', password_hash=generate_password_hash('testpassword', method='pbkdf2:sha256'), date_of_birth=datetime.strptime('2000-01-01', '%Y-%m-%d'))
            db.session.add(test_user)
            db.session.commit()
            # Create a test admin user
            test_admin = User(username='adminuser', email='adminuser@example.com', password_hash=generate_password_hash('adminpassword', method='pbkdf2:sha256'), date_of_birth=datetime.strptime('1980-01-01', '%Y-%m-%d'), admin=True)
            db.session.add(test_admin)
            db.session.commit()
            # Create a test account for the user
            test_account = Account(name="Test Account", balance=1000.0, currency="USD", country="USA", user_id=test_user.id)
            db.session.add(test_account)
            db.session.commit()
            yield client
        with app.app_context():
            db.drop_all()
            
def test_register(testing_client):
    response = testing_client.post('/register', json={
        'username': 'newuser',
        'password': 'newpassword',
        'email': 'newuser@example.com',
        'date_of_birth': '2000-01-01'
    })
    assert response.status_code == 200
    assert b'username' in response.data

def test_login(testing_client):
    response = testing_client.post('/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 200
    token = response.json['token']
    assert token is not None
    print(f"Generated Token: {token}")

def test_create_admin(testing_client):
    response = testing_client.post('/login', json={
        'username': 'adminuser',
        'password': 'adminpassword'
    })
    assert response.status_code == 200
    token = response.json['token']
    assert token is not None  # Ensure token is generated

    response = testing_client.post('/create_admin', json={
        'username': 'newadmin',
        'password': 'newadminpassword'
    }, headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 201
    print(response.json)

    
def test_transfer_money(testing_client):
    # Login as test user to get the token
    response = testing_client.post('/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 200
    token = response.json['token']

    # Create a second account for the transfer
    response = testing_client.post('/accounts', json={
        'name': 'Second Account',
        'currency': 'USD',
        'country': 'USA'
    }, headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 201
    second_account_number = response.json['account']['account_number']

    # Transfer money between accounts
    response = testing_client.post('/transactions', json={
        'from_account_number': '12345678901234567890',
        'to_account_number': second_account_number,
        'amount': 100.0
    }, headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert b'Transfer successful' in response.data

def test_get_accounts(testing_client):
    # Login as test user to get the token
    response = testing_client.post('/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 200
    token = response.json['token']

    # Get accounts
    response = testing_client.get('/accounts', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert b'Test Account' in response.data
    print(response.json)

def test_user_portal(testing_client):
    # Login as test user to get the token
    response = testing_client.post('/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 200
    token = response.json['token']

    # Access user portal
    response = testing_client.get('/user_portal', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    print(response.json)
    

def test_admin_portal(testing_client):
    # Login as admin to get the token
    response = testing_client.post('/login', json={
        'username': 'adminuser',
        'password': 'adminpassword'
    })
    assert response.status_code == 200
    token = response.json['token']

    # Access admin portal
    response = testing_client.get('/admin_portal', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert b'adminuser' in response.data
    assert b'testuser' in response.data