from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from models.user import User
from extensions import db
import requests
import json

register_bp = Blueprint("register", __name__)

# Add your reCAPTCHA secret key
RECAPTCHA_SECRET_KEY = "6Lc1ouUqAAAAAIRcLgWhIN3_7CWhi3iTQPtY0Rdm"
# For v3, we need to set a threshold (0.0 to 1.0, where 1.0 is very likely human)
RECAPTCHA_SCORE_THRESHOLD = 0.5

@register_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        recaptcha_response = request.form.get("g-recaptcha-response")

        if not recaptcha_response:
            flash("Please complete the reCAPTCHA challenge.", "error")
            return redirect(url_for("register.register"))
        
        verify_data = {
            'secret': RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }
        
        r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=verify_data)
        result = r.json()
        
        if not result.get('success'):
            flash("reCAPTCHA verification failed. Please try again.", "error")
            return redirect(url_for("register.register"))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists. Please choose a different one.", "error")
            return redirect(url_for("register.register"))

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for("login.login"))

    return render_template("register.html")