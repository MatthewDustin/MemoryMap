from functools import wraps
from flask import session, redirect, url_for

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            # Redirect to login page if the user is not authenticated
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function