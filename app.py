
import asyncio
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import re
import os
import mysql.connector

app = Flask(__name__)
app.debug = True

app.config["SESSION_TYPE"] = "filesystem"
Session(app)


returned_data = []

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def login_required(f):
    @wraps(f)

    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        else:
           pass
        return f(*args, **kwargs)
    return decorated_function



@app.template_global(name='zip')
def _zip(*args, **kwargs): #to not overwrite builtin zip in globals
    return __builtins__.zip(*args, **kwargs)

@app.route("/", methods=["GET", "POST"])
@login_required
def index(icons=[['#','box']]):
    return render_template('index.html')

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        if "file" not in request.files:
            return render_template('upload.html', data="Please select a file.")
        
        file = request.files["file"]
        
        if file.filename == "":
            return render_template('upload.html', data="Please select a file.")
        
        if file:
            user_id = session.get("user_id")
            upload_dir = os.path.join("uploads", str(user_id))
            os.makedirs(upload_dir, exist_ok=True)
            file_path = os.path.join(upload_dir, file.filename)
            file.save(file_path)
            return render_template('upload.html', data="File uploaded successfully.")
        
    return render_template('upload.html')

################################login##################################

@app.route("/login", methods=["GET", "POST"])
def login():

    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("login.html", data="Make sure you type in your username.")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("login.html", data="Make sure you type in your password.")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return render_template("login.html", data="Invalid username and/or password")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")
        pw_two = request.form.get("confirmation")

        usernames = db.execute("SELECT username FROM users;")
        emails = db.execute("SELECT email FROM users;")
        print(username)
        #print(usernames[0]['username'])
        if username == '' or password == '' or pw_two == '' or email == '':
             return render_template("register.html", data="you need to fill out all of the fields!")
        if is_valid_email(email) == 0:
             return render_template("register.html", data="invalid email please provide a real email address")

        i=0
        while i<len(usernames):
            if usernames[i]['username'] == username:
                 return render_template("register.html", data="Username already in use!")
            elif emails[i]['email'] == email:
                 return render_template("register.html", data="Email already in use!")
            i+=1

        if password == pw_two:
            if is_valid_password(password) == 1:
                hash = generate_password_hash(password)
                print(hash)
                db.execute("INSERT INTO users (username, hash, email) VALUES(?, ?, ?);", username, hash, email)
                session_id = db.execute("SELECT id FROM users WHERE username = ? ", username)
                session["user_id"] = session_id[0]["id"]
                
            else:
                return "Password must be at least 8 characters long and contain at least one number and one uppercase letter"

            return redirect("/")

        else:
            return render_template("register.html", data="passwords don't mach!")

    else:
        return render_template("register.html")


def is_valid_password(password):
    if len(password) < 8:
        return 4
    if not re.search(r'[A-Z]', password):
        return 2
    if not re.search(r'\d', password):
        return 3
    return 1

def is_valid_email(email):
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(email_pattern, email):
        return 1
    else:
        return 0