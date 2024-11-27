import pytest
from iebank_api.models import Account, User, db
from werkzeug.security import generate_password_hash
from iebank_api import app

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
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            # Create a test user
            test_user = User(username='testuser', password_hash=generate_password_hash('testpassword', method='pbkdf2:sha256'))
            db.session.add(test_user)
            db.session.commit()
            yield client
            db.session.remove()
            db.drop_all()

