from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from models.user import User
from extensions import db
import requests

import json
from time import gmtime, strftime

register_bp = Blueprint("register", __name__)

# Add your reCAPTCHA secret key
RECAPTCHA_SECRET_KEY = "6Lc1ouUqAAAAAIRcLgWhIN3_7CWhi3iTQPtY0Rdm"
# For v3, we need to set a threshold (0.0 to 1.0, where 1.0 is very likely human)
RECAPTCHA_SCORE_THRESHOLD = 0.5

# Requirement functions
def containsUpper(password):
    for char in password:
        if('A' <= char <= 'Z'):
            return True
    return False
def containsLower(password):
    for char in password:
        if('a' <= char <= 'z'):
            return True
    return False
def containsDigit(password):
    for char in password:
        if(char.isdigit()):
            return True
    return False

def logAction(username, action, message):
    log = {
        "user": username,
        "time": strftime("%Y-%m-%d %H:%M:%S", gmtime()),
        "action": action,
        "message": message
    }

    try:
        with open('ActionLogs.json', 'r') as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}

    if 'logs' not in data:
        data['logs'] = []
    
    data['logs'].append(log)

    with open('ActionLogs.json', 'w') as file:
        json.dump(data, file, indent=4)
        
@register_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        passwordVerify = request.form.get("passwordVerify")

        # Check if password meets requirements
        if(not (len(password) >= 8 and 
            containsUpper(password) and 
            containsLower(password) and 
            containsDigit(password))):

            logAction(username, "Registration", "Invalid Password")

            flash("Password must meet requirements", "error")
            return redirect(url_for("register.register"))

        # Check if passwords match
        if(password != passwordVerify):
            logAction(username, "Registration", "Passwords didn't match")

            flash("Passwords do not match. Please try again.", "error")
            return redirect(url_for("register.register"))
        
        recaptcha_response = request.form.get("g-recaptcha-response")

        if not recaptcha_response:
            logAction(username, "Registration", "reCAPTCHA not complete")

            flash("Please complete the reCAPTCHA challenge.", "error")
            return redirect(url_for("register.register"))
        
        verify_data = {
            'secret': RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }
        
        r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=verify_data)
        result = r.json()
        
        if not result.get('success'):
            logAction(username, "Registration", "reCAPTCHA Failed")

            flash("reCAPTCHA verification failed. Please try again.", "error")
            return redirect(url_for("register.register"))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            logAction(username, "Registration", "Username already exists")

            flash("Username already exists. Please choose a different one.", "error")
            return redirect(url_for("register.register"))

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        logAction(username, "Registration", "Successful!")
        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for("login.login"))

    return render_template("register.html")