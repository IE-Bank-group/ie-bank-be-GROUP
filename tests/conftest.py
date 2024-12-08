import pytest
from iebank_api.models import Account, User, db
from werkzeug.security import generate_password_hash
from iebank_api import app
from datetime import datetime

@pytest.fixture(scope='function', autouse=True)
def clean_db():
    with app.app_context():
        db.drop_all()
        db.create_all()
        yield
        db.session.remove()
        db.drop_all()

@pytest.fixture(scope='module')
def testing_client():
     # Ensure app configuration has necessary keys for testing
    app.config['SECRET_KEY'] = 'test-secret-key'
    app.config['JWT_SECRET_KEY'] = 'test-jwt-secret-key'
    app.config['TESTING'] = True  # Enable Flask testing mode
    
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
            test_account = Account(name="Test Account", balance=1000.0, currency="USD", status="Active", country="USA", user_id=test_user.id)
            db.session.add(test_account)
            db.session.commit()
            yield client
        with app.app_context():
            db.drop_all()