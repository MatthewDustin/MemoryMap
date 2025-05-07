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
import logging
import signal
import sys
import os
import bcrypt
import mysql.connector
from types import FrameType

from flask import Flask, redirect, url_for, session, render_template, request, send_from_directory
from sshtunnel import SSHTunnelForwarder
from auth.auth import login_required
from utils.logging import logger
from flask_wtf import CSRFProtect
from dotenv import load_dotenv
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, EqualTo
from flask_wtf.recaptcha import RecaptchaField

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Login')
    
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    recaptcha = RecaptchaField()
    submit = SubmitField('Register')

class PostForm(FlaskForm):
    imageLink = StringField('Image Link', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Post')
    
def get_db_connection():
    """Establish and return a new database connection."""
    return mysql.connector.connect(
        host=os.getenv('DATABASE_URL', 'localhost'),
        user="admin",
        password="memorymap",
        database="memorymapdb"
    )
    
load_dotenv()
csrf = CSRFProtect()

def create_app():
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True, static_folder='static', template_folder='templates')
    app.config.from_mapping(
        SECRET_KEY="EXTRASECRET",
        DATABASE=(
            f"host={os.environ.get('MYSQL_SERVICE_HOST')} "
            f"user={os.environ.get('MYSQL_USER')} password={os.environ.get('MYSQL_PASSWORD')}"
        )
    )

    # Load current software version into the CONFIG
    try:
        with open("VERSION", "r") as f:
            app.config["BUILD_VERSION"] = f.read().strip()
    except FileNotFoundError:
        app.config["BUILD_VERSION"] = "Unknown"

    # load the instance config, if it exists, when not testing
    app.config.from_prefixed_env()
    app.config.from_pyfile("config.py", silent=True)
    gunicorn_logger = logging.getLogger("gunicorn.error")
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)


    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    csrf.init_app(app)

    # Error handlers
    @app.errorhandler(404)
    def page_not_found(error):
        return render_template("404.html", error_code=True), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        return render_template("500.html", error_code=True), 500

    @app.errorhandler(503)
    def service_unavailable(error):
        return render_template("503.html", error_code=True), 503

    @app.errorhandler(504)
    def gateway_timeout(error):
        return render_template("504.html", error_code=True), 504

    return app

app = create_app()
app.config["RECAPTCHA_PUBLIC_KEY"] = "6LcfqzArAAAAADxnvcdPJDLqK954Zo5NqAbvdHKn"
app.config["RECAPTCHA_PRIVATE_KEY"] = "6LcfqzArAAAAAM7otJzdKWW-Oc5l-_Dw0GMhZQ2F"

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
    form = PostForm()
    posts = get_all_posts()
    return render_template('home.html', user=session.get('user'), form=form, posts=posts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Check if the user is already authenticated
        if is_authenticated():
            return redirect(url_for('index'))
        # Add your authentication logic here
        hash = checkLoginAttempt(username)
        if verify_password(password, hash):  # Replace with real auth
            session['authenticated'] = True
            session['user'] = username
            
            return redirect(url_for('index'))
        else:
            session['error_message'] = 'Invalid username or password'
            return redirect(url_for('login'))
    
    return render_template('login.html',
                           form=form,
                           error_message=session.pop('error_message', None))


@app.route('/logout')
def logout():
    # Clear the user session
    session.clear()
    logger.info("User logged out")
    return render_template('logout.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    usernames = getUsernames()
    # passwords = getPasswords()  # Removed or commented out as getPasswords is not defined
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        if username in usernames:
            session['error_message'] = 'Username already exists'
            return redirect(url_for('register'))
        # if password not strong enough
        if len(password) < 8:
            session['error_message'] = 'Password must be at least 8 characters long'
            return redirect(url_for('register'))
        password = hash(password)
        if (addUser(username, password)):
            session['authenticated'] = True
            session['user'] = username
            
            return redirect(url_for('index'))
        else:
            session['error_message'] = 'Failed to register user'
            return redirect(url_for('register'))
    return render_template('register.html', 
                            form=form,
                            error_message=session.pop('error_message', None))

@app.route('/create-post', methods=['POST'])
@login_required
def create_post():
    form = PostForm()
    posts = get_all_posts()
    # Get the data from the request
    data = request.get_json()
    lat = data.get('lat')
    lng = data.get('lng')
    imageLink = data.get('imageLink')
    description = data.get('description')

    #convert lat and lng to one string
    location = f"{lat},{lng}"
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Fetch the user_id for the authenticated user
        cursor.execute("SELECT user_id FROM users WHERE username = %s", (session.get('user'),))
        user_id = cursor.fetchone()
        if not user_id:
            return {'error': 'User not found'}, 404
        
        user_id = user_id[0]  # Extract the ID from the result tuple
        
        cursor.execute(
            "INSERT INTO posts (location, imageLink, description, user_id) VALUES (%s, %s, %s, %s)",
            (location, imageLink, description, user_id)
        )
        conn.commit()
        cursor.close()
        conn.close()
    except mysql.connector.Error as err:
        logger.error(f"Error: {err}")
        return render_template('home.html', error_message='Failed to create post', form=form, posts=posts), 500

    posts = get_all_posts()
    return render_template('home.html', user=session.get('user'), form=form, posts=posts)

@app.route('/get-post', methods=['GET'])
@login_required
def get_post():
    location = request.args.get('location')
    if not location:
        return {'error': 'Location is required'}, 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM posts WHERE location = %s", (location,))
        post = cursor.fetchone()
        cursor.close()
        conn.close()

        if not post:
            return {'error': 'Post not found'}, 404

        return {
            'user': session.get('user'),
            'imageLink': post['imageLink'],
            'description': post['description']
        }
    except mysql.connector.Error as err:
        logger.error(f"Error: {err}")
        return {'error': 'Failed to fetch post data'}, 500

def get_all_posts():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM posts")
        posts = cursor.fetchall()
        #filter out posts with location without a comma
        posts = [post for post in posts if ',' in post['location']]
        
        #get all usernames from the database
        cursor.execute("SELECT user_id, username FROM users")
        users = cursor.fetchall()
        #replace user_id with username in posts
        for post in posts:
            for user in users:
                if post['user_id'] == user['user_id']:
                    post['username'] = user['username']
                    break
        #remove user_id from posts
        for post in posts:
            del post['user_id']
        #replace location with lat and lng
        for post in posts:
            lat, lng = post['location'].split(',')
            post['lat'] = lat
            post['lng'] = lng
        for post in posts:
            del post['location']
        cursor.close()
        conn.close()
        return posts
    except mysql.connector.Error as err:
        logger.error(f"Error: {err}")
        return []

@app.route('/copyright')
def copyright():
    return render_template('copyright.html')

@app.route('/test-db')
def test_db():
    try:
        usernames = getUsernames()
        return f"Connected! Usernames: {usernames}"
    except Exception as e:
        return f"Error: {e}"

def verify_password(input_password: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(input_password.encode(), stored_hash.encode())
  
def hash(password):
    salt = bcrypt.gensalt()
    # Hash the password with the salt
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password.decode()

def checkLoginAttempt(username):
    # Check if the username and password match in the database
    # set URL for database
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()
        password = result[2] if result else None
        cursor.close()
        conn.close()
        return password
    except mysql.connector.Error as err:
        logger.error(f"Error: {err}")
        return False

def addUser(username, password):
    # Add user to the database
    # set URL for database
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except mysql.connector.Error as err:
        logger.error(f"Error: {err}")
        return False
        
        
def getUsernames():
    # Fetch usernames from the database
    # set URL for database
    #user=os.getenv('MYSQL_USER', 'your-username'),
    #password=os.getenv('MYSQL_PASSWORD', 'your-password'),

    try:
        conn = get_db_connection()
        # connect to the database
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users")
        usernames = [row[0] for row in cursor.fetchall()]
        cursor.close()
        conn.close()
        return usernames
    except mysql.connector.Error as err:
        logger.error(f"Error: {err}")
        return []

def shutdown_handler(signal_int: int, frame: FrameType) -> None:
    logger.info(f"Caught Signal {signal.strsignal(signal_int)}")

    from utils.logging import flush

    flush()

    # Safely exit program
    sys.exit(0)

@app.after_request
def add_header(response):
    #response.headers['Content-Type'] = 'text/html; charset=utf-8'
    return response



app.config["TEMPLATES_AUTO_RELOAD"] = True

if __name__ == "__main__":
    # Running application locally, outside of a Google Cloud Environment

    # handles Ctrl-C termination
    signal.signal(signal.SIGINT, shutdown_handler)

    app.run(host="localhost", port=8080, debug=False)
    
else:
    # handles Cloud Run container termination
    signal.signal(signal.SIGTERM, shutdown_handler)
