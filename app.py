from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:2807@localhost/user_log"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False, unique=True)
    gmail = db.Column(db.String(200), nullable=False, unique=True)
    password = db.Column(db.Text, nullable=False)
    role = db.Column(db.Integer, nullable=False) 
    log_entries = db.relationship('Log', backref='author', lazy=True)


class Log(db.Model):
    __tablename__ = "logs"
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    check_in = db.Column(db.Time, nullable=False)
    check_out = db.Column(db.Time, nullable=False)
    task = db.Column(db.Text, nullable=False)
    total_hours = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


with app.app_context():
    db.create_all()

@app.route("/")
def home():
    return render_template("main.html", page="first_page", is_logged_in=("user_id" in session))


@app.route("/home")
def home1():
    if "user_id" in session:
        user = User.query.get(session["user_id"])
        return render_template("main.html", page="home", name=user.name, is_logged_in=True)

    return redirect(url_for("home"))

@app.context_processor
def inject_user():
    return {
        "name": session.get("name"),
        "is_logged_in": "user_id" in session
    }


@app.route("/register")
def show_register():
    return render_template("main.html", page="register", is_logged_in="user_id" in session)


@app.route("/register", methods=["POST"])
def register():
    selected_role = request.form.get('role')
    name = request.form["name"]
    gmail = request.form["gmail"]
    password = request.form["password"]
    confirm = request.form["confirm"]

    if password != confirm:
        return render_template("main.html", page="register", error="Passwords do not match", is_logged_in="user_id" in session)

    existing_user = User.query.filter((User.name == name) | (User.gmail == gmail)).first()

    if existing_user:
        return render_template("main.html", page="register", error="User already exists! Try another name or gmail.")

    try:
        hashed = generate_password_hash(password)

        if selected_role == "admin":
            role_value = 1
        else:
            role_value = 0

        new_user = User(
            name=name,
            gmail=gmail,
            password=hashed,
            role=role_value
        )
        
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))

    except:
        db.session.rollback()
        return render_template("main.html", page="register", error="Registration Failed", is_logged_in="user_id" in session)


@app.route("/login")
def show_login():
    return render_template("main.html", page="login", is_logged_in="user_id" in session)


@app.route("/login", methods=["POST"])
def login():
    name = request.form["name"]
    gmail = request.form["gmail"]
    password = request.form["password"]

    user = User.query.filter_by(name=name, gmail=gmail).first()

    if user and check_password_hash(user.password, password):
        session["user_id"] = user.id
        session["name"] = user.name
        
        if user.role == 1:
            return redirect(url_for("user_logs"))
        else:
            return render_template("main.html", page="logs", name=name, is_logged_in=True)

    return render_template("main.html", page="login", error="Invalid Login", is_logged_in=False)


@app.route("/logs", methods=["POST"])
def logs():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    date = request.form["date"]
    check_in = request.form["check_in"]
    check_out = request.form["check_out"]
    task = request.form["task"]

    try:
        t1 = datetime.strptime(check_in, "%H:%M")
        t2 = datetime.strptime(check_out, "%H:%M")

        total_hours = (t2 - t1).total_seconds() / 3600
        if total_hours < 0:
            return "Check-out time must be after check-in time"

        new_log = Log(
            date = date,
            check_in=t1.time(),
            check_out=t2.time(),
            task=task,
            total_hours=total_hours,
            user_id=session["user_id"]
        )

        db.session.add(new_log)
        db.session.commit()

        return redirect("/list")

    except:
        db.session.rollback()
        return render_template("main.html", page="logs", error="Failed to add log", is_logged_in=True)
    
    
@app.route("/user_logs", methods=["GET", "POST"])
def user_logs():
    if "user_id" not in session:
        return redirect(url_for("login"))

    current_user = User.query.get(session["user_id"])
    if current_user.role != 1:
        return "Access Denied"

    if request.method == "GET":
        user_names = User.query.all()
        return render_template("main.html", page="user_logs", user_names=user_names, is_logged_in=True)

    if request.method == "POST":
        uid = request.form.get("user_id")
        logs = Log.query.filter_by(user_id=uid).all()
        user = User.query.get(uid)
        return render_template("main.html", page="view_logs", logs=logs, name=user.name, is_logged_in=True)


@app.route("/view_logs")
def view_user_logs(user_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    current_user = User.query.get(session["user_id"])
    if current_user.role != 1:   
        return "Access Denied"

    logs = Log.query.filter_by(user_id=user_id).all()
    user = User.query.get(user_id)

    return render_template("main.html", page="view_logs", logs=logs, name=user.name, is_logged_in=True)


@app.route("/list")
def list_log():
    if "user_id" not in session:
        return redirect(url_for("login"))

    data = Log.query.filter_by(user_id=session["user_id"]).all()
    return render_template("main.html", page="list", data=data, is_logged_in=True)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)