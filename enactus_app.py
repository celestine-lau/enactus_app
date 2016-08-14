from flask import Flask, request, redirect, url_for
from flask_dance.contrib.google import make_google_blueprint, google
from flask_sqlalchemy import SQLAlchemy
import json

app = Flask(__name__)
app.secret_key = "DEVELOPMENT_KEY"
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://enactus:<localpassword>@localhost/enactusdb"
app.config['SQLALCHEMY_ECHO'] = True

blueprint = make_google_blueprint(
    client_id="test",
    client_secret="test",
    scope=["profile", "email"]
)
app.register_blueprint(blueprint, url_prefix="/login")
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



@app.route("/")
def index():
    if not google.authorized:
        return redirect(url_for("google.login"))
    resp = google.get("/plus/v1/people/me")
    print resp.text
    assert resp.ok, resp.text
    jsresp = resp.json()
    return "You are {name} [{email}] on Google".format(email=jsresp["emails"][0]["value"], name=jsresp["displayName"])
	
@app.route("/user/<username>", methods=["PUT"])
def create_user(username):
    try:
        user = json.loads(request.data)
        fname = user.get("first_name", "")
        lname = user.get("last_name", "")
    except ValueError:
        return "Bad request"
    return "Creating user %s with name %s %s" % (username, fname, lname)

@app.route("/user/<username>", methods=["GET"])
def show_user(username):
    return "Displaying user %s" % username