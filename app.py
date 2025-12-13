from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import random 
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = "supersecretkey"

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:2807@localhost/user_log"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT"))
app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS") == "True"
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")

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
def user_name():
    if "name" in session:
        return {"name": session["name"]}
    return {"name": ""}


@app.route("/register")
def show_register():
    return render_template("main.html", page="register", is_logged_in="user_id" in session)

@app.route("/register", methods=["POST"])
def register():
    name = request.form.get("name")
    gmail = request.form.get("gmail")
    password = request.form.get("password")
    confirm = request.form.get("confirm")
    selected_role = request.form.get("role")

    if password != confirm:
        return render_template("main.html", page="register", error="Passwords do not match")

    if User.query.filter((User.name == name) | (User.gmail == gmail)).first():
        return render_template("main.html", page="register", error="User already exists!")

    otp = str(random.randint(100000, 999999))
    session.update({
        "otp": otp,
        "temp_name": name,
        "temp_gmail": gmail,
        "temp_password": password,
        "temp_role": selected_role
    })

    send_otp_email(gmail, otp)

    return render_template("main.html", page="verify_otp")

    
@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    input_otp = request.form.get("otp")

    if input_otp != session.get("otp"):
        return render_template("main.html", page="verify_otp", error="Invalid OTP! Try again.")

    new_user = User(
        name=session["temp_name"],
        gmail=session["temp_gmail"],
        password=generate_password_hash(session["temp_password"]),
        role=1 if session["temp_role"] == "admin" else 0
    )

    db.session.add(new_user)
    db.session.commit()

    for key in ["otp", "temp_name", "temp_gmail", "temp_password", "temp_role"]:
        session.pop(key, None)

    return redirect(url_for("login"))

def send_otp_email(receiver, otp):
    sender = app.config["MAIL_USERNAME"]
    password = app.config["MAIL_PASSWORD"]

    msg = MIMEText(f"Your OTP for registration is: {otp}")
    msg["Subject"] = "Your OTP Verification Code"
    msg["From"] = sender
    msg["To"] = receiver

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, receiver, msg.as_string())
        return True
    except Exception as e:
        print("Email Error:", e)
        return False


@app.route("/login")
def show_login():
    if "user_id" in session:
        return redirect(url_for("home"))  
    return render_template("main.html", page="login")


@app.route("/login", methods=["POST"])
def login():
    if "user_id" in session:
        return "You must logout before logging in another user."

    name = request.form["name"]
    gmail = request.form["gmail"]
    password = request.form["password"]

    user = User.query.filter_by(name=name, gmail=gmail).first()

    if user and check_password_hash(user.password, password):
        session["user_id"] = user.id
        session["name"] = user.name
        session["role"] = user.role   

        if user.role == 1:
            return redirect(url_for("admin_screen"))
        else:
            return redirect(url_for("screen"))

    return render_template("main.html", page="login", error="Invalid name or password")

@app.route("/screen")
def screen():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    return render_template("main.html",page="screen",name=session["name"],role=session["role"],is_logged_in=True)

@app.route("/admin_screen")
def admin_screen():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != 1:
        return "Access Denied"

    return render_template("main.html",page="admin_screen",name=session["name"], role=session["role"], is_logged_in=True)

    
@app.route("/user_logs", methods=["GET", "POST"])
def user_logs():
    if "user_id" not in session:
        return redirect(url_for("login"))

    current_user = User.query.get(session["user_id"])
    if current_user.role != 1:
        return "Access Denied"

    if request.method == "GET":
        user_names = User.query.all()
        return render_template("main.html", page="user_logs", user_names=user_names,role=session["role"], is_logged_in=True)

    if request.method == "POST":
        uid = request.form.get("user_id")
        logs = Log.query.filter_by(user_id=uid).all()
        user = User.query.get(uid)
        return render_template("main.html", page="view_logs", logs=logs, name=user.name,role=session["role"], is_logged_in=True)

    
@app.route("/delete_log/<int:log_id>", methods=["POST"])
def delete_log(log_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    log = Log.query.get(log_id)
    if not log:
        return "Log not found", 404

    user = User.query.get(session["user_id"])
    is_admin = (user.role == 1)

    if (log.user_id != session["user_id"]) and (not is_admin):
        return "Unauthorized", 403

    db.session.delete(log)
    db.session.commit()

    if is_admin:
        logs = Log.query.filter_by(user_id=log.user_id).all()
        user = User.query.get(log.user_id)
        return render_template("main.html", page="view_logs", logs=logs, name=user.name, is_logged_in=True)

    logs = Log.query.filter_by(user_id=session["user_id"]).all()
    return render_template("main.html", page="list", data=logs, is_logged_in=True)


@app.route("/edit_log/<int:log_id>", methods=["GET"])
def edit_log(log_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    log = Log.query.get(log_id)
    if not log:
        return "Log not found", 404

    user = User.query.get(session["user_id"])
    is_admin = (user.role == 1)

    if (log.user_id != session["user_id"]) and (not is_admin):
        return "Unauthorized", 403

    return render_template("main.html", page="edit_logs", log=log, is_logged_in=True)


@app.route("/update_log/<int:log_id>", methods=["POST"])
def update_log(log_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    log = db.session.get(Log, log_id)
    if not log:
        return "Log not found", 404

    user = db.session.get(User, session["user_id"])
    is_admin = (user.role == 1)

    if (log.user_id != session["user_id"]) and (not is_admin):
        return "Unauthorized", 403

    date = request.form.get("date")
    check_in = request.form.get("check_in")
    check_out = request.form.get("check_out")
    task = request.form.get("task")

    def parse_time(value):
        try:
            return datetime.strptime(value, "%H:%M:%S")
        except ValueError:
            return datetime.strptime(value, "%H:%M")

    try:
        log.date = datetime.strptime(date, "%Y-%m-%d").date()

        t1 = parse_time(check_in)
        t2 = parse_time(check_out)

        total_hours = round((t2 - t1).total_seconds() / 3600, 2)
        if total_hours < 0:
            return render_template("main.html", page="edit_logs", log=log, error="Check-out must be after check-in", is_logged_in=True)

        log.check_in = t1.time()
        log.check_out = t2.time()
        log.task = task
        log.total_hours = total_hours

        db.session.commit()

        if is_admin:
            logs = Log.query.filter_by(user_id=log.user_id).all()
            u = db.session.get(User, log.user_id)
            return render_template("main.html", page="view_logs", logs=logs, name=u.name, is_logged_in=True)

        logs = Log.query.filter_by(user_id=session["user_id"]).all()
        return render_template("main.html", page="list", data=logs, is_logged_in=True)

    except Exception:
        return render_template("main.html", page="edit_logs", log=log, error="Failed to update", is_logged_in=True)


@app.route("/add_logs", methods=["GET", "POST"])
def add_logs():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("main.html", page="add_logs", role=session["role"], is_logged_in=True)

    date = request.form.get("date")
    check_in = request.form.get("check_in")
    check_out = request.form.get("check_out")
    task = request.form.get("task")

    existing_log = Log.query.filter_by(user_id=session["user_id"], date=date).first()
    if existing_log:
        return render_template("main.html", page="add_logs", error="A log for this date already exists!", role=session["role"], is_logged_in=True)

    try:
        t1 = datetime.strptime(check_in, "%H:%M")
        t2 = datetime.strptime(check_out, "%H:%M")

        total_hours = round((t2 - t1).total_seconds() / 3600, 2)
        if total_hours < 0:
            return render_template( "main.html", page="add_logs", error="Check-out must be after check-in", role=session["role"], is_logged_in=True)

        new_log = Log(
            date=date,
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
        return render_template("main.html", page="add_logs", role=session["role"], is_logged_in=True)


@app.route("/list", methods=["GET","POST"])
def list_log():
    if "user_id" not in session:
        return redirect(url_for("login"))

    data = Log.query.filter_by(user_id=session["user_id"]).all()
    return render_template("main.html", page="list", data=data,role=session["role"], is_logged_in=True)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)