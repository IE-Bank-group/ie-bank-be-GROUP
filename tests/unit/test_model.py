from iebank_api.models import Account, User, db
import pytest
from datetime import datetime
from werkzeug.security import generate_password_hash
import uuid
from iebank_api import app

@pytest.fixture(scope='function', autouse=True)
def clean_db():
    with app.app_context():
        db.drop_all()
        db.create_all()
        yield
        db.session.remove()
        db.drop_all()
        
@pytest.fixture
def new_user():
    unique_username = f'testuser_{uuid.uuid4()}'
    return User(username=unique_username, password_hash=generate_password_hash('testpassword', method='pbkdf2:sha256'), date_of_birth=datetime.strptime('2000-01-01', '%Y-%m-%d'))

def test_create_account(new_user):
    """
    GIVEN an Account model
    WHEN a new Account is created
    THEN check the name, account_number, balance, currency, status, created_at, country, and user_id fields are defined correctly
    """
    account = Account(
        name='John Doe',
        currency='USD',
        balance=0.0,
        country='USA',
        user_id=new_user.id
    )
    assert account.name == 'John Doe'
    assert len(account.account_number) == 20 #since account number is random, test the string length
    assert account.currency == 'USD'
    assert account.balance == 0.0
    assert account.status == 'Active'
    assert account.country == 'USA'
    assert account.user_id == new_user.id