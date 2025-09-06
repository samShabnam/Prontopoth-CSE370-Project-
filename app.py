import os
import re
import random
import smtplib
import pymysql
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from dotenv import load_dotenv

# environment variables load kore
load_dotenv()

app=Flask(__name__)
app.secret_key=os.getenv("SECRET_KEY", "dev-secret-change-me")

# File uploads
UPLOAD_FOLDER=os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS={"png", "jpg", "jpeg", "gif"}
app.config["UPLOAD_FOLDER"]=UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"]=5*1024*1024 

#Database connection er jonno
def get_db():
    return pymysql.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "protnopoth_db"),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
        charset="utf8mb4"
    )

# email theke role dibeee
def infer_role_from_email(email: str) -> str:
    domain=email.split("@")[-1].lower().strip()
    # Check exact suffixes with specificity first
    if domain.endswith("g.bracu.ac.bd"):
        return "Archaeologist"
    if domain.endswith("gov.bd"):
        return "Admin"
    if domain.endswith("bracu.ac.bd"):
        return "Museum Manager"
    if domain.endswith("outlook.com"):
        return "Caretaker"
    return "General User"

#otp pathabeee SMTPPPPPP -_-
def send_otp_email(to_email: str, otp: str) -> bool:
    gmail_user=os.getenv("GMAIL_USER")
    gmail_pass=os.getenv("GMAIL_PASS")
    subject="Your PROTNOPOTH OTP Verification Code"
    text=f"Your OTP code is: {otp}\n\nThis code expires in 10 minutes."

    msg=MIMEMultipart()
    msg["From"]=gmail_user
    msg["To"]=to_email
    msg["Subject"]=subject
    msg.attach(MIMEText(text, "plain"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(gmail_user, gmail_pass)
        server.sendmail(gmail_user, to_email, msg.as_string())
    return True
def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# to control login prerequisite
from functools import wraps
def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please verify your email to access this page.") #session control thingggzz
            return redirect(url_for("home"))
        return view_func(*args, **kwargs)
    return wrapper

# Routes
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login")
def login():
    return render_template("login.html")
#haniyar file a aseee.

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method=="POST":
        name=request.form.get("name", "").strip()
        nid=request.form.get("nid", "").strip()
        email=request.form.get("email", "").strip()
        phone=request.form.get("phone", "").strip()
        password=request.form.get("password", "")

        # gap thaakle flash noti ashbe
        if not name or not nid or not email or not password:
            flash("Please fill all required fields.")
            return redirect(url_for("signup"))

        # role assign
        role=infer_role_from_email(email)

        # hash password (even though login isn't connected yet)
        password_hash=generate_password_hash(password)

        # OTP
        otp=f"{random.randint(100000, 999999)}"
        otp_expires=datetime.utcnow()+timedelta(minutes=10)

        # detabase insert
        conn=get_db()
        with conn.cursor() as cur:
            # Check existing user by email
            cur.execute("SELECT id FROM users WHERE email=%s", (email,))
            existing=cur.fetchone()
            if existing:
                flash("An account with this email already exists.")
                return redirect(url_for("signup"))

            cur.execute(
                """
                INSERT INTO users (name, nid, email, phone, password_hash, role, is_verified, otp_code, otp_expires)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (name, nid, email, phone or None, password_hash, role, 0, otp, otp_expires.strftime("%Y-%m-%d %H:%M:%S"))
            )
            user_id=cur.lastrowid
        # Send OTP email
        sent=send_otp_email(email, otp)
        if not sent:
            flash("Could not send OTP email. Please contact support or check email settings.")
        return redirect(url_for("verification", email=email))

    return render_template("signup.html")

@app.route("/verification", methods=["GET", "POST"])
def verification():
    if request.method=="GET":
        email=request.args.get("email", "")
        return render_template("verification.html", email=email)

    # POST
    email=request.form.get("email", "").strip()
    otp=request.form.get("otp", "").strip()
    if not email or not otp:
        flash("Email and OTP are required.")
        return redirect(url_for("verification", email=email))

    conn=get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user=cur.fetchone()
        if not user:
            flash("User not found.")
            return redirect(url_for("home"))

        if not user["otp_code"] or not user["otp_expires"]:
            flash("No OTP pending for this account.")
            return redirect(url_for("home"))

        # check OTP and expiry
        exp=user["otp_expires"]
        if isinstance(exp, str):
            # (depending on driver, may return string—handle robustly)
            exp=datetime.strptime(exp, "%Y-%m-%d %H:%M:%S")

        if user["otp_code"]!=otp:
            flash("Invalid OTP. Please try again.")
            return redirect(url_for("verification", email=email))

        if datetime.utcnow() > exp:
            flash("OTP expired. Please sign up again to receive a new OTP.")
            return redirect(url_for("signup"))

        # verified & "sign-in"
        cur.execute(
            "UPDATE users SET is_verified=1, otp_code=NULL, otp_expires=NULL WHERE id=%s",
            (user["id"],)
        )
        session["user_id"]=user["id"]
        flash("Verification successful. Welcome!")
        return redirect(url_for("dashboard"))
@app.route("/dashboard")
@login_required
def dashboard():
    user_id=session.get("user_id")
    conn=get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT id, name, role FROM users WHERE id=%s", (user_id,))
        user=cur.fetchone()
        if not user:
            flash("User not found.")
            return redirect(url_for("home"))


    return render_template("dashboard.html", user=user)


@app.route("/profile")
@login_required
def profile():
    user_id=session.get("user_id")
    conn=get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT id, name, nid, email, phone, role, profile_pic, is_verified FROM users WHERE id=%s", (user_id,))
        user=cur.fetchone()
        if not user:
            flash("User not found.")
            return redirect(url_for("home"))
        return render_template("profile.html", user=user)
@app.route("/editprofile", methods=["GET", "POST"])
@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    user_id=session.get("user_id")

    if request.method=="GET":
        conn=get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT id, name, nid, email, phone FROM users WHERE id=%s", (user_id,))
            user=cur.fetchone()
            if not user:
                flash("User not found.")
                return redirect(url_for("profile"))
            return render_template("edit_profile.html", user=user)
    # POST
    name=request.form.get("name", "").strip()
    nid=request.form.get("nid", "").strip()
    email=request.form.get("email", "").strip()
    phone=request.form.get("phone", "").strip()

    # if info required 
    if not name or not nid or not email:
        flash("Name, NID and Email are required.")
        return redirect(url_for("edit_profile"))

    # handle picture upload file
    profile_pic_filename=None
    file=request.files.get("profile_pic")
    if file and file.filename:
        if allowed_file(file.filename):
            safe_name=secure_filename(file.filename)
            root, ext=os.path.splitext(safe_name)
            unique_name=f"user{user_id}_{int(datetime.utcnow().timestamp())}{ext}"
            save_path=os.path.join(app.config["UPLOAD_FOLDER"], unique_name)
            file.save(save_path)
            profile_pic_filename=unique_name
    conn=get_db()
    with conn.cursor() as cur:
        # keep role unchanged; just ensure email is unique across *other* users
        cur.execute("SELECT id FROM users WHERE email=%s AND id<>%s", (email, user_id))
        if cur.fetchone():
            flash("This email is already in use.")
            return redirect(url_for("edit_profile"))

        # do update 
        if profile_pic_filename:
            cur.execute(
                """
                UPDATE users
                SET name=%s, nid=%s, email=%s, phone=%s, profile_pic=%s
                WHERE id=%s
                """,
                (name, nid, email, phone or None, profile_pic_filename, user_id)
            )
        else:
            cur.execute(
                """
                UPDATE users
                SET name=%s, nid=%s, email=%s, phone=%s
                WHERE id=%s
                """,
                (name, nid, email, phone or None, user_id)
            )
        flash("Profile updated.")
        return redirect(url_for("profile"))
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("home"))

if __name__ == "__main__":
    # For local development
    app.run(debug=True)
