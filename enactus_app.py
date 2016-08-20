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


def populate_attrs_from_keys(dst, src, keys):
    """ Populates an object's attributes with values from a source dict corresponding to given keys.
    Ignores elements in the source dict that don't exist
    Args:
        dst: the target object
        src: the source dict
        keys: the keys to populate, if they exist

    Returns: the target object

    """
    for key in keys:
        if (key in src):
            setattr(dst, key, src[key])
    return dst

# Request handlers


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


@app.route("/user/<userid>", methods=["GET"])
@authorize_check(1)
def show_user(userid):
    user = User.query.filter_by(id=userid).first()
    if user is None:
        return error_response(error_codes.NO_SUCH_USER, "No such user")
    return success_response(user)


@app.route("/user", methods=["PUT"])
@authorize_check(1)
def update_user():
    ### Update user fields
    # Handles POST request to update user. Request body must contain user object.
    # The fields that can be updated are: display_name, quiz_completed, goals_set and learning_profile
    # Throws a 400 error if request is malformed
    # Throws a 401 error if trying to change details of a user with higher privilege
    jsondata = request.get_json()
    if jsondata is None:
        abort(400)
    userid = jsondata.get("id", -1)
    user = User.query.filter_by(id=userid).first()
    if user is None:
        return error_response(error_codes.NO_SUCH_USER, "No such user")
    if user.email != session["username"] and session["privilege"] <= user.privilege:
        abort(401)
    if jsondata.get("display_name", "") == "":
        return error_response(error_codes.DISPLAY_NAME_NOT_SPECIFIED, "Display name must be specified")
    populate_attrs_from_keys(user, jsondata, ["display_name", "quiz_completed", "goals_set", "learning_profile"])
    db.session.commit()
    return success_response(user)


@app.route("/user", methods=["POST"])
@authorize_check(3)
def create_user():
    jsondata = request.get_json()
    if jsondata is None:
        abort(400)
    if jsondata.get("email", "") == "":
        return error_response(error_codes.EMAIL_NOT_SPECIFIED, "Email must be specified")
    requested_email = jsondata["email"]
    user = User.query.filter_by(email=requested_email).first()
    if user is not None:
        return error_response(error_codes.USER_ALREADY_EXISTS, "User already exists")
    requested_privilege = jsondata.get("privilege", 0)
    if requested_privilege < 1 or requested_privilege > 4:
        return error_response(error_codes.INVALID_PRIVILEGE_LEVEL, "Invalid privilege specified")
    if session["privilege"] == 3 and requested_privilege > 2:
        return error_response(error_codes.INSUFFICIENT_PRIVILEGE, "Insufficient privilege to perform action")
    if jsondata.get("display_name", "") == "":
        return error_response(error_codes.DISPLAY_NAME_NOT_SPECIFIED, "Display name must be specified")
    user = User(requested_email, requested_privilege)
    populate_attrs_from_keys(user, jsondata, ["display_name", "quiz_completed", "goals_set", "learning_profile"])
    db.session.add(user)
    db.session.commit()
    return success_response(user)

@app.route("/evil")
@authorize_check(5)
def evil():
    return "You are %s. Anyone can access this?" % session["username"]

