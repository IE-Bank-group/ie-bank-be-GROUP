from iebank_api import db, app
from iebank_api.models import User, Account
import pytest
from werkzeug.security import generate_password_hash

@pytest.fixture
def testing_client():
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            # Create a test user
            test_user = User(username='testuser', password_hash=generate_password_hash('testpassword', method='pbkdf2:sha256'))
            db.session.add(test_user)
            db.session.commit()
            # Create a test admin user
            test_admin = User(username='adminuser', password_hash=generate_password_hash('adminpassword', method='pbkdf2:sha256'), admin=True)
            db.session.add(test_admin)
            db.session.commit()
            # Create a test account for the user
            test_account = Account(name="Test Account", account_number="12345678901234567890", balance=1000.0, currency="USD", status="Active", country="USA", user_id=test_user.id)
            db.session.add(test_account)
            db.session.commit()
            yield client
        with app.app_context():
            db.drop_all()

def test_get_accounts(testing_client):
    """
    GIVEN a Flask application
    WHEN the '/accounts' page is requested (GET)
    THEN check the response is valid
    """
    response = testing_client.get('/accounts', headers={'Authorization': 'Basic dGVzdHVzZXI6dGVzdHBhc3N3b3Jk'})
    assert response.status_code == 200

def test_dummy_wrong_path(testing_client):
    """
    GIVEN a Flask application
    WHEN the '/wrong_path' page is requested (GET)
    THEN check the response is valid
    """
    response = testing_client.get('/wrong_path')
    assert response.status_code == 404

def test_get_account(testing_client):
    """
    GIVEN a Flask application
    WHEN the '/accounts/<id>' page is requested (GET)
    THEN check the response is valid
    """
    response = testing_client.get('/accounts/1', headers={'Authorization': 'Basic dGVzdHVzZXI6dGVzdHBhc3N3b3Jk'})
    assert response.status_code == 200

def test_transfer_money(testing_client):
    """
    GIVEN a Flask application
    WHEN the '/transfer' page is requested (POST)
    THEN check the response is valid
    """
    response = testing_client.post('/transfer', json={
        'from_account': '12345678901234567890',
        'to_account': '09876543210987654321',
        'amount': 100.0
    }, headers={'Authorization': 'Basic dGVzdHVzZXI6dGVzdHBhc3N3b3Jk'})
    assert response.status_code == 404  # Since the recipient account does not exist

def test_add_funds(testing_client):
    """
    GIVEN a Flask application
    WHEN the '/add_funds' page is requested (POST)
    THEN check the response is valid
    """
    response = testing_client.post('/add_funds', json={
        'account_number': '12345678901234567890',
        'amount': 500.0
    }, headers={'Authorization': 'Basic YWRtaW51c2VyOmFkbWlucGFzc3dvcmQ='})
    assert response.status_code == 200
    assert response.json['account']['balance'] == 1500.0