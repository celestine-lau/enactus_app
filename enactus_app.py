from flask import Flask, json, request, redirect, url_for, session, escape, abort, render_template, jsonify
from oauthlib.oauth2.rfc6749.errors import InvalidGrantError, TokenExpiredError, OAuth2Error
from flask_dance.contrib.google import make_google_blueprint, google
from flask_sqlalchemy import SQLAlchemy
from pymysql import IntegrityError
from enactus_keys import ServerParams
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
import error_codes
import constants

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
    task_statuses = db.relationship("TaskStatus", back_populates="user")

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


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)
    max_points = db.Column(db.Integer, nullable=False)
    type = db.Column(db.Integer, nullable=False)
    category = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(1000))
    image = db.Column(db.String(255))
    url = db.Column(db.String(255))

    def __repr__(self):
        return "<Task %d: %r,%r,%r,%r,%r>" % \
               (self.id, self.name, self.max_points, self.type, self.category, self.url)

    def serialize(self):
        return {
            "id":self.id,
            "name":self.name,
            "max_points":self.max_points,
            "type":self.type,
            "category":self.category,
            "description":self.description,
            "image":self.image,
            "url":self.url
        }


class TaskStatus(db.Model):
    __tablename__ = "taskstatus"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    task_id = db.Column(db.Integer, db.ForeignKey("task.id"))
    status = db.Column(db.Integer, nullable=False, default=0)
    points = db.Column(db.Integer, nullable=False, default=0)
    __table_args__ = ( db.UniqueConstraint("user_id", "task_id", name="unique_user_task"), )
    task = db.relationship("Task")
    user = db.relationship("User", back_populates="task_statuses")

    def serialize(self):
        return {
            "user_id":self.user_id,
            "task": self.task.serialize(),
            "status": self.status,
            "points": self.points
        }


class ResponseJson(object):

    def __init__(self, success, code, data):
        self.success = success
        self.code = code
        self.data = data

    def serialize(self):
        serialdata = self.serialize_helper(self.data)
        print serialdata
        return {
            "success": self.success,
            "code": self.code,
            "data": serialdata
        }

    def serialize_helper(self, obj):
        if hasattr(obj, "__iter__"):
            return [self.serialize_helper(elem) for elem in obj]
        if callable(getattr(obj, "serialize", None)):
            return obj.serialize()
        return obj


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
    ### Shows a user's details
    # Any user can view any other user's details
    user = User.query.filter_by(id=userid).first()
    if user is None:
        return error_response(error_codes.NO_SUCH_USER, "No such user")
    return success_response(user)


@app.route("/user", methods=["PUT"])
@authorize_check(1)
def update_user():
    ### Update user fields
    # Handles PUT request to update user. Request body must contain user object.
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
    ### Create new user
    # Handles POST request to create user. Requires privilege level FF(3) and above
    # User object must be specified in request body. All fields except id will be processed.
    # Privilege 3 users may only create privilege 1 and 2 users
    # Privilege 4 users can create users of any privilege (1-4)
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


@app.route("/task/<taskid>", methods=["GET"])
@authorize_check(1)
def show_task(taskid):
    ### Show a task details
    # Any user can view any task's details
    # TODO: Check if it is necessary to prevent users from viewing tasks that are unassigned/unavailable
    task = Task.query.filter_by(id=taskid).first()
    if task is None:
        return error_response(error_codes.NO_SUCH_TASK, "No such task")
    return success_response(task)


@app.route("/tasks", methods=["GET"])
@authorize_check(1)
def get_tasks():
    ### Show tasks that a user is assigned
    # Returns an array of taskStatus
    user = User.query.filter_by(email=session["username"]).first()
    if user is None:
        abort(400)
    return success_response(user.task_statuses)


@app.route("/task", methods=["PUT"])
@authorize_check(3)
def update_task():
    ### Updates details about a task
    # Requires privilege level FF(3) and above
    # Image URL is checked against allowed image file extensions
    # Task URL must end with .html
    # IMPORTANT NOTE: client side Javascript must handle HTML escaping of URLs returned if rendered as HTML
    jsondata = request.get_json()
    if jsondata is None:
        abort(400)
    taskid = jsondata.get("id", -1)
    task = Task.query.filter_by(id=taskid).first()
    if task is None:
        return error_response(error_codes.NO_SUCH_TASK, "No such task")
    if "name" not in jsondata or jsondata["name"] == "":
        return error_response(error_codes.INVALID_TASK_DETAILS, "Name must be specified")
    try:
        max_points = int(jsondata["max_points"])
        type = int(jsondata["type"])
        category = int(jsondata["category"])
    except KeyError:
        return error_response(error_codes.INVALID_TASK_DETAILS, "max_points, type and category must be specified")
    except ValueError:
        return error_response(error_codes.INVALID_TASK_DETAILS, "Invalid numerical value(s)")
    if max_points <= 0 or max_points > 10000:
        return error_response(error_codes.INVALID_TASK_DETAILS, "Max points must be between 1 and 10000")
    type = min(max(type, 0), constants.MAX_TASK_TYPE)
    category = min(max(category, 0), constants.MAX_CATEGORY)
    if "image" in jsondata:
        try:
            tokens = jsondata["image"].split(".")
            if len(tokens) == 1 or tokens[-1] not in constants.ALLOWED_IMAGE_EXTENSIONS:
                return error_response(error_codes.INVALID_IMAGE_URL, "Image URL is invalid")
        except AttributeError:
            task.image = None
    if "url" in jsondata:
        try:
            tokens = jsondata["url"].split(".")
            if len(tokens) == 1 or tokens[-1] != "html":
                return error_response(error_codes.INVALID_TASK_URL, "Task URL must end with .html")
        except AttributeError:
            task.url = None
    task.max_points = max_points
    task.type = type
    task.category = category
    populate_attrs_from_keys(task, jsondata, ["name", "description", "image", "url"])
    try:
        db.session.commit()
    except IntegrityError:
        return error_response(error_codes.DUPLICATE_TASK_NAME, "A task with that name already exists")
    return success_response(task)


@app.route("/task", methods=["POST"])
@authorize_check(3)
def create_task():
    ### Creates a new task
    # Requires privilege level FF(3) and above
    # Image URL is checked against allowed image file extensions
    # Task URL must end with .html
    # IMPORTANT NOTE: client side Javascript must handle HTML escaping of URLs returned if rendered as HTML
    jsondata = request.get_json()
    if jsondata is None:
        abort(400)
    if "name" not in jsondata:
        return error_response(error_codes.INVALID_TASK_DETAILS, "Name must be specified")
    taskname = jsondata["name"]
    task = Task.query.filter_by(name=taskname).first()
    if task is not None:
        return error_response(error_codes.DUPLICATE_TASK_NAME, "Task with that name already exists")
    try:
        max_points = int(jsondata["max_points"])
        type = int(jsondata["type"])
        category = int(jsondata["category"])
    except KeyError:
        return error_response(error_codes.INVALID_TASK_DETAILS, "max_points, type and category must be specified")
    except ValueError:
        return error_response(error_codes.INVALID_TASK_DETAILS, "Invalid numerical value(s)")
    if max_points <= 0 or max_points > 10000:
        return error_response(error_codes.INVALID_TASK_DETAILS, "Max points must be between 1 and 10000")
    type = min(max(type, 0), constants.MAX_TASK_TYPE)
    category = min(max(category, 0), constants.MAX_CATEGORY)
    task = Task()
    if "image" in jsondata:
        try:
            tokens = jsondata["image"].split(".")
            if len(tokens) == 1 or tokens[-1] not in constants.ALLOWED_IMAGE_EXTENSIONS:
                return error_response(error_codes.INVALID_IMAGE_URL, "Image URL is invalid")
        except AttributeError:
            task.image = None
    if "url" in jsondata:
        try:
            tokens = jsondata["url"].split(".")
            if len(tokens) == 1 or tokens[-1] != "html":
                return error_response(error_codes.INVALID_TASK_URL, "Task URL must end with .html")
        except AttributeError:
            task.url = None
    task.max_points = max_points
    task.type = type
    task.category = category
    populate_attrs_from_keys(task, jsondata, ["name", "description", "image", "url"])
    try:
        db.session.add(task)
        db.session.commit()
    except IntegrityError:
        return error_response(error_codes.DUPLICATE_TASK_NAME, "A task with that name already exists")
    return success_response(task)

@app.route("/assign", methods=["POST"])
@authorize_check(3)
def assign_tasks():
    ### Assign tasks to users
    # Requires privilege level FF(3) and above
    # Expects a json object of the form { "users": [id1, id2, ...], "tasks": [id1, id2, ...] }
    # Ignores user and task ids that don't exist.
    # For each user/task pair, will set taskStatus to "available" if currently in the "unavailable"
    # or nonexistent state
    jsondata = request.get_json()
    if jsondata is None:
        abort(400)
    if "users" not in jsondata or "tasks" not in jsondata:
        return error_response(error_codes.USERS_OR_TASKS_NOT_SPECIFIED, "Must specify users and tasks")
    users = []
    tasks = []
    try:
        for userid in jsondata["users"]:
            try:
                users.append(int(userid))
            except ValueError:
                pass
    except TypeError:
        try:
            users.append(int(jsondata["users"]))
        except ValueError:
            return error_response(error_codes.INVALID_PARAMETERS, "users must be an id or array of ids")
    try:
        for taskid in jsondata["tasks"]:
            try:
                tasks.append(int(taskid))
            except ValueError:
                pass
    except TypeError:
        try:
            tasks.append(int(jsondata["tasks"]))
        except ValueError:
            return error_response(error_codes.INVALID_PARAMETERS, "tasks must be an id or array of ids")
    assign_tasks_helper(users, tasks)
    return success_response("")

@app.route("/assignAll", methods=["POST"])
@authorize_check(3)
def assign_all_tasks():
    ### Assign tasks to users
    # Requires privilege level FF(3) and above
    # Expects a json object of the form { "users": [id1, id2, ...], "tasks": [id1, id2, ...] }
    # Ignores user and task ids that don't exist.
    # For each user/task pair, will set taskStatus to "available" if currently in the "unavailable"
    # or nonexistent state
    jsondata = request.get_json()
    if jsondata is None:
        abort(400)
    if "users" not in jsondata:
        return error_response(error_codes.USERS_OR_TASKS_NOT_SPECIFIED, "Must specify users")
    users = []
    tasks = []
    try:
        for userid in jsondata["users"]:
            try:
                users.append(int(userid))
            except ValueError:
                pass
    except TypeError:
        try:
            users.append(int(jsondata["users"]))
        except ValueError:
            return error_response(error_codes.INVALID_PARAMETERS, "users must be an id or array of ids")
    for result in Task.query.all():
        tasks.append(result.id)
    assign_tasks_helper(users, tasks)
    return success_response("")


def assign_tasks_helper(userids, taskids):
    """
    Helper method to assign specified tasks to specified users
    :param userids: a list of user ids to assign the tasks to
    :param taskids: a list of task ids to assign to the users
    :return: true if successful
    """
    users = User.query.filter(User.id.in_(userids)).all()
    tasks = Task.query.filter(Task.id.in_(taskids)).all()
    for user in users:
        existing_taskids = {}
        for taskstatus in user.task_statuses:
            existing_taskids[taskstatus.task_id] = taskstatus
        for task in tasks:
            if task.id in existing_taskids:
                taskstatus = existing_taskids[task.id]
                if taskstatus.status == constants.STATUS_UNAVAILABLE:
                    taskstatus.status = constants.STATUS_AVAILABLE
            else:
                taskstatus = TaskStatus()
                taskstatus.task = task
                taskstatus.user = user
                taskstatus.task_id = task.id
                taskstatus.user_id = user.id
                taskstatus.status = constants.STATUS_AVAILABLE
                taskstatus.points = 0
                db.session.add(taskstatus)
    db.session.commit()
    return True