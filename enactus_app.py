from flask import Flask, json, request, redirect, url_for, session, escape, abort, render_template, jsonify
from oauthlib.oauth2.rfc6749.errors import InvalidGrantError, TokenExpiredError, OAuth2Error
from flask_dance.contrib.google import make_google_blueprint, google
from flask_sqlalchemy import SQLAlchemy
from enactus_keys import ServerParams
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
import error_codes

server_params = ServerParams()
app = Flask(__name__)
app.secret_key = server_params.secret_key
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://enactus:%s@localhost/enactusdb" % server_params.local_db_password
app.config["SQLALCHEMY_ECHO"] = True
app.config["JSON_SORT_KEYS"] = False
blueprint = make_google_blueprint(
    client_id=server_params.google_clientid,
    client_secret=server_params.google_clientsecret,
    scope=["profile", "email"]
)
app.register_blueprint(blueprint, url_prefix="/login")
handler = RotatingFileHandler("messages.log", maxBytes=1048576, backupCount=1)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    display_name = db.Column(db.String(80), nullable=False)
    privilege = db.Column(db.Integer, nullable=False)
    quiz_completed = db.Column(db.Boolean)
    goals_set = db.Column(db.Boolean)
    learning_profile = db.Column(db.String(255))

    def __init__(self, email, privilege):
        self.email = email
        self.privilege = privilege

    def __repr__(self):
        return "<User %d: %r,%r,%r,%r,%r,%r>" % \
               (self.id, self.email, self.display_name, self.privilege, self.quiz_completed, self.goals_set,
                self.learning_profile)

    def serialize(self):
        return {
            "id":self.id,
            "email":self.email,
            "display_name":self.display_name,
            "privilege":self.privilege,
            "quiz_completed":self.quiz_completed,
            "goals_set":self.goals_set,
            "learning_profile":self.learning_profile
        }


class ResponseJson(object):

    def __init__(self, success, code, data):
        self.success = success
        self.code = code
        self.data = data


    def serialize(self):
        return {
            "success": self.success,
            "code": self.code,
            "data": self.data.serialize() if callable(getattr(self.data, "serialize", None)) else self.data
        }


# Overall Helper Functions
# ---------------------------------------------------------------

def success_response(data):
    """ Returns a successful JSON response with specified data

    Args:
        data: the data to return

    Returns: the successful JSON HTTP response

    """
    resp = ResponseJson(True, 0, data)
    return jsonify(resp.serialize())


def error_response(code, message):
    """ Returns an error JSON response with specified message

    Args:
        code: the error code
        message: the error message

    Returns: the error JSON HTTP response

    """
    resp = ResponseJson(False, code, message)
    return jsonify(resp.serialize())

def authorize_check(level):
    """ Decorator generator for checking whether the user is logged in and authorized to the level required for
        this function

    Args:
        level: The minimum privilege level needed to execute the function

    Returns:
        The decorator
    """
    def authorize_decorator(func):
        @wraps(func)
        def func_wrapper(*args, **kwargs):
            if "username" not in session:
                return redirect(url_for("google.login"))
            priv = session.get("privilege", 0)
            if (priv < level):
                abort(401)
            return func(*args, **kwargs)
        return func_wrapper
    return authorize_decorator


@app.errorhandler(401)
def unauthorized(error):
    return render_template("unauthorized.html"), 401


@app.route("/")
def index():
    if not google.authorized:
        return redirect(url_for("google.login"))
    try:
        resp = google.get("/plus/v1/people/me")
    except TokenExpiredError:
        return redirect(url_for("google.login"))
    assert resp.ok, resp.text
    jsresp = resp.json()
    email = jsresp["emails"][0]["value"]
    user = User.query.filter_by(email=email).first()
    if (user is None):
        return "You are not a registered user on Enactus Learning Platform Alpha"
    session["username"] = email
    session["privilege"] = user.privilege
    return render_template("index.html")
    #return "You are {name} [{email}] on Google".format(email=email, name=jsresp["displayName"])


@app.route("/user/<username>", methods=["PUT"])
def create_user(username):
    try:
        user = json.loads(request.data)
        fname = user.get("first_name", "")
        lname = user.get("last_name", "")
    except ValueError:
        return "Bad request"
    return "Creating user %s with name %s %s" % (username, fname, lname)

@app.route("/user/<id>", methods=["GET"])
@authorize_check(1)
def show_user(id):
    user = User.query.filter_by(id=id).first()
    if (user is None):
        return error_response(error_codes.NO_SUCH_USER, "No such user")
    return success_response(user)


@app.route("/evil")
@authorize_check(5)
def evil():
    return "You are %s. Anyone can access this?" % session["username"]

