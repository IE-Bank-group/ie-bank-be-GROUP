from iebank_api.models import Account, User, db
import pytest
from datetime import datetime
from werkzeug.security import generate_password_hash
import uuid


@pytest.fixture(scope='function', autouse=True)
def clean_db():
        db.drop_all()
        db.create_all()
        yield
        db.session.remove()
        db.drop_all()
        
@pytest.fixture
def new_user():
    unique_username = f'pytestuser_{uuid.uuid4()}'
    return User(username=unique_username, password_hash=generate_password_hash('testpassword', method='pbkdf2:sha256'))

def test_create_account(new_user):
    """
    GIVEN an Account model
    WHEN a new Account is created
    THEN check the name, account_number, balance, currency, status, created_at, country, and user_id fields are defined correctly
    """
    account = Account(
        name='John Doe',
        account_number='12345678901234567890',
        currency='USD',
        balance=0.0,
        status='Active',
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
    assert isinstance(account.created_at, datetime)