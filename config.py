import os
import urllib.parse
from azure.identity import DefaultAzureCredential

class Config(object): 
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEBUG = False
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'dev-secret-key')

class LocalConfig(Config):
    SQLALCHEMY_DATABASE_URI = 'sqlite:///local.db'
    DEBUG = True

class GithubCIConfig(Config):
    SQLALCHEMY_DATABASE_URI = 'sqlite:///test.db'
    DEBUG = True

class DevelopmentConfig(Config):
    DEBUG = True

    def __init__(self):
        credential = DefaultAzureCredential()
        dbuser = urllib.parse.quote(os.getenv('DBUSER', 'default_user'))
        dbpass = credential.get_token(
            'https://ossrdbms-aad.database.windows.net').token
        dbhost = os.getenv('DBHOST', 'localhost')
        dbname = os.getenv('DBNAME', 'development_db')
        self.SQLALCHEMY_DATABASE_URI = f'postgresql://{dbuser}:{dbpass}@{dbhost}/{dbname}'

class UATConfig(Config):
    DEBUG = True

    def __init__(self):
        credential = DefaultAzureCredential()
        dbuser = urllib.parse.quote(os.getenv('DBUSER', 'default_user'))
        dbpass = credential.get_token(
            'https://ossrdbms-aad.database.windows.net').token
        dbhost = os.getenv('DBHOST', 'localhost')
        dbname = os.getenv('DBNAME', 'uat_db')
        self.SQLALCHEMY_DATABASE_URI = f'postgresql://{dbuser}:{dbpass}@{dbhost}/{dbname}'
        
class ProductionConfig(Config):
    DEBUG = False

    def __init__(self):
        credential = DefaultAzureCredential()
        dbuser = urllib.parse.quote(os.getenv('DBUSER', 'default_user'))
        dbpass = credential.get_token(
            'https://ossrdbms-aad.database.windows.net').token
        dbhost = os.getenv('DBHOST', 'localhost')
        dbname = os.getenv('DBNAME', 'production_db')
        self.SQLALCHEMY_DATABASE_URI = f'postgresql://{dbuser}:{dbpass}@{dbhost}/{dbname}'