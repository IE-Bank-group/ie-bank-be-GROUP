from iebank_api import app
from iebank_api.models import Account
import pytest



def test_get_accounts(testing_client):
    """
    GIVEN a Flask application
    WHEN the '/accounts' page is requested (GET)
    THEN check the response is valid
    """
    response = testing_client.get('/accounts')
    assert response.status_code == 200

def test_dummy_wrong_path():
    """
    GIVEN a Flask application
    WHEN the '/wrong_path' page is requested (GET)
    THEN check the response is valid
    """
    with app.test_client() as client:
        response = client.get('/wrong_path')
        assert response.status_code == 404
        
def test_get_account(testing_client):
    """
    GIVEN a Flask application
    WHEN the '/accounts/<int:id>' page is requested (GET)
    THEN check the response is valid and the account is retrieved
    """
    _ = testing_client.post('/accounts', json={'name': 'John Doe', 'currency': '€', 'country':'Spain'})
    
    account = Account.query.filter_by(name='John Doe')[0]
    response = testing_client.get(f'/accounts/{account.id}')
    account = Account.query.get(account.id)
    
    assert response.status_code == 200
    assert response.json['country'] == account.country
    

def test_create_account(testing_client):
    """
    GIVEN a Flask application
    WHEN the '/accounts' page is posted to (POST)
    THEN check the response is valid
    """
    response = testing_client.post('/accounts', json={'name': 'John Doe', 'currency': '€', 'country':'Spain'})
    assert response.status_code == 200
    
def test_delete_account(testing_client):
    """
    GIVEN a Flask application
    WHEN the '/accounts/<int:id>' page is deleted (DELETE)
    THEN check the response is valid and the account is deleted
    """
    _ = testing_client.post('/accounts', json={'name': 'John Doe', 'currency': '€', 'country':'Spain'})
    
    account = Account.query.filter_by(name='John Doe')[0]
    response = testing_client.delete(f'/accounts/{account.id}')
    assert response.status_code == 200
    
    accounts = Account.query.filter_by(name='John Doe').all()
    assert accounts == []
    
def test_update_account(testing_client):
    """
    GIVEN a Flask application
    WHEN the '/accounts/<int:id>' page is put (PUT)
    THEN check the response is valid and the account is updated
    """
    _ = testing_client.post('/accounts', json={'name': 'John Doe', 'currency': '€', 'country':'Spain'})
    account = Account.query.filter_by(name='John Doe')[0]
    
    response = testing_client.put(f'/accounts/{account.id}', json={'name': 'Daniel', 'country': 'Argentina'})
    account = Account.query.get(account.id)
    
    
    assert response.status_code == 200
    assert account.name == 'Daniel'
    assert account.country == 'Argentina'
     

def test_create_account_data(testing_client):
    """
    GIVEN a Flask application
    WHEN the '/accounts' page is posted to (POST)
    THEN check the account data is correct
    """
    _ = testing_client.post('/accounts', json={'name': 'John Doe', 'currency': '€', 'country':'Spain'})
    account = Account.query.filter_by(name='John Doe')[0]
    
    assert account.name == 'John Doe'
    assert account.currency == '€'
    assert account.account_number != None
    assert account.balance == 0.0
    assert account.status == 'Active'
    assert account.country == 'Spain'