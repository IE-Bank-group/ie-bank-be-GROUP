from iebank_api import app, db
from iebank_api.models import User, Account

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'Account': Account}

if __name__ == '__main__':
    app.run(debug=True)