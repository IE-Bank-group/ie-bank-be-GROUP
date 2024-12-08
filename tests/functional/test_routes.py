from iebank_api import db, app
from iebank_api.models import User, Account
import pytest
from werkzeug.security import generate_password_hash
from flask_jwt_extended import create_access_token
from datetime import datetime

@pytest.fixture
def testing_client():
    """Setup a testing client with a clean database for each test"""
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            # Create a test user
            test_user = User(
                username='testuser',
                email='testuser@example.com',
                password_hash=generate_password_hash('testpassword', method='pbkdf2:sha256'),
                date_of_birth=datetime.strptime('2000-01-01', '%Y-%m-%d')
            )
            db.session.add(test_user)
            db.session.commit()
            # Create a test admin user
            test_admin = User(
                username='adminuser',
                email='adminuser@example.com',
                password_hash=generate_password_hash('adminpassword', method='pbkdf2:sha256'),
                date_of_birth=datetime.strptime('1980-01-01', '%Y-%m-%d'),
                admin=True
            )
            db.session.add(test_admin)
            db.session.commit()
            # Create a test account for the user
            test_account = Account(
                name="Test Account",
                balance=1000.0,
                currency="USD",
                country="USA",
                user_id=test_user.id
            )
            db.session.add(test_account)
            db.session.commit()
            yield client
        with app.app_context():
            db.drop_all()


def test_register(testing_client):
    """Test user registration"""
    response = testing_client.post('/register', json={
        'username': 'newuser',
        'password': 'newpassword',
        'email': 'newuser@example.com',
        'date_of_birth': '2000-01-01'
    })
    assert response.status_code == 201
    assert b'username' in response.data


def test_login(testing_client):
    """Test user login"""
    response = testing_client.post('/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 200
    token = response.json.get('token')
    assert token is not None


def test_create_admin(testing_client):
    response = testing_client.post('/login', json={
        'username': 'adminuser',
        'password': 'adminpassword'
    })
    assert response.status_code == 200
    token = response.json.get('token')
    assert token is not None

    response = testing_client.post('/create_admin', json={
        'username': 'newadmin',
        'password': 'newadminpassword',
        'email': 'newadmin@example.com',
        'date_of_birth': '1985-01-01'
    }, headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 201
    assert response.json['username'] == 'newadmin'

def test_transfer_money(testing_client):
    # Login as test user to get the token
    response = testing_client.post('/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 200
    token = response.json.get('token')

    # Retrieve the test user's existing account
    response = testing_client.get('/accounts', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    user_accounts = response.json.get('accounts', [])
    assert len(user_accounts) > 0

    from_account_number = user_accounts[0]['account_number']

    # Create a second account
    response = testing_client.post('/accounts', json={
        'name': 'Second Account',
        'currency': 'USD',
        'country': 'USA',
        'balance': 500.0
    }, headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 201

    # Capture the generated account number
    second_account_number = response.json.get('account_number')
    assert second_account_number is not None

    # Transfer money between accounts
    response = testing_client.post('/transactions', json={
        'from_account_number': from_account_number,
        'to_account_number': second_account_number,
        'amount': 100.0
    }, headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert b'Transfer successful' in response.data



def test_get_accounts(testing_client):
    """Test fetching user accounts"""
    response = testing_client.post('/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 200
    token = response.json.get('token')

    # Get accounts
    response = testing_client.get('/accounts', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert b'Test Account' in response.data

def test_user_portal(testing_client):
    """Test accessing the user portal"""
    response = testing_client.post('/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 200
    token = response.json.get('token')

    # Access user portal
    response = testing_client.get('/user_portal', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert b'testuser' in response.data
    assert b'Test Account' in response.data


def test_admin_portal(testing_client):
    """Test accessing the admin portal"""
    response = testing_client.post('/login', json={
        'username': 'adminuser',
        'password': 'adminpassword'
    })
    assert response.status_code == 200
    token = response.json.get('token')

    # Access admin portal
    response = testing_client.get('/admin_portal', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert b'adminuser' in response.data
    assert b'testuser' in response.data
