# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import signal
import sys
import os
from types import FrameType

from flask import Flask, redirect, url_for, session, render_template, request, send_from_directory

from utils.logging import logger

app = Flask(__name__)
app.secret_key = "EXTRASECRET"

@app.route('/templates/<path:filename>')
def serve_template(filename):
    return send_from_directory(os.path.join(app.root_path, 'templates'), filename, mimetype='text/html')

def is_authenticated():
    return session.get('authenticated', False)


@app.route("/")
def index() -> str:
    if not is_authenticated():
        logger.info("User not authenticated, redirecting to login")
        return redirect(url_for('login'))

    logger.info("User authenticated, showing home page")

    logger.info(logField="custom-entry", arbitraryField="custom-entry")
    logger.info("Child logger with trace Id.")

    return render_template('home.html', user=session.get('user'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Add your authentication logic here
        if username == 'admin' and password == 'password':  # Replace with real auth
            session['authenticated'] = True
            session['user'] = username
            return redirect(url_for('hello'))
        else:
            session['error_message'] = 'Invalid username or password'
            return redirect(url_for('login'))
    return render_template('login.html', 
                         error_message=session.pop('error_message', None))

@app.route('/register', methods=['GET', 'POST'])
def register():
    usernames = getUsernames()
    passwords = getPasswords()
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        password = hash(password)
        
        session['authenticated'] = True
        session['user'] = username
        return redirect(url_for('hello'))
        #else:
            #session['error_message'] = 'Invalid username or password'
            #return redirect(url_for('login'))
    return render_template('register.html', 
                         error_message=session.pop('error_message', None))

def hash(password):
    # Hash the password using a secure hashing algorithm (e.g., bcrypt)
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()

def getUsernames():
    # Fetch usernames from the database
    import sqlite3
    # set URL for database
    
    conn = sqlite3.connect('database.db')  # connect to your database
    # connect to the database
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users")
    usernames = cursor.fetchall()
    cursor.close()
    return [user[0] for user in usernames]

def shutdown_handler(signal_int: int, frame: FrameType) -> None:
    logger.info(f"Caught Signal {signal.strsignal(signal_int)}")

    from utils.logging import flush

    flush()

    # Safely exit program
    sys.exit(0)

@app.after_request
def add_header(response):
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    return response

app.config["TEMPLATES_AUTO_RELOAD"] = True

if __name__ == "__main__":
    # Running application locally, outside of a Google Cloud Environment

    # handles Ctrl-C termination
    signal.signal(signal.SIGINT, shutdown_handler)

    app.run(host="localhost", port=8080, debug=True)
else:
    # handles Cloud Run container termination
    signal.signal(signal.SIGTERM, shutdown_handler)
