from flask import abort
from flask_login import current_user
from functools import wraps

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.role != 'admin':
            abort(403)  # Forbidden
        return func(*args, **kwargs)
    return wrapper