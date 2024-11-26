import pytest
from iebank_api.models import Account, User
from iebank_api.__init__ import db, app
from werkzeug.security import generate_password_hash


@pytest.fixture(scope='module')
def testing_client():
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


   with app.test_client() as testing_client:
       yield testing_client


   with app.app_context():
       db.drop_all()
