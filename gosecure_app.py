#!/usr/bin/env python

import hashlib
import os
import pickle
import time
from functools import wraps

import flask.ext.login as flask_login
from flask import (
    Flask, render_template, request, Response, flash, redirect, url_for)

from forms import (
    LoginForm, InitialSetupForm, UserForm, WifiForm, VpnPskForm,
    ResetToDefaultForm, StatusForm)
from scripts.pi_mgmt import (
    pi_reboot, pi_shutdown, start_ssh_service, update_client)
from scripts.rpi_network_conn import add_wifi, internet_status, reset_wifi
from scripts.vpn_server_conn import (
    set_vpn_params, reset_vpn_params, start_vpn, stop_vpn, restart_vpn,
    vpn_status, vpn_configuration_status)

app = Flask(__name__)
login_manager = flask_login.LoginManager()
login_manager.init_app(app)


# Flask-Login functions (for regular Pages)

# users = {"admin":{"password":"2074ad04839ae517751e5948ae13f0e3c90d186c9c9bbd29c3c88b9c6000dba5", "salt":"uOMbInZTYYpiCGvEaH8Byw==\n"}}
# default username=admin password=gosecure, user is prompted to change if default is being used.
with open("/home/pi/goSecure_Web_GUI/users_db.p", "rb") as fin:
    users = pickle.load(fin)


class User(flask_login.UserMixin):
    pass


@login_manager.user_loader
def user_loader(username):
    if username not in users:
        return

    user = User()
    user.id = username
    return user


@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    if username not in users:
        return

    user = User()
    user.id = username

    # DO NOT ever store passwords in plaintext and always compare password
    # hashes using constant-time comparison!
    if user_validate_credentials(request.form['username'], request.form['password']):
        user.is_authenticated = True

    return user


@login_manager.unauthorized_handler
def unauthorized_handler():
    flash("Unauthorized, please log in.", "error")
    return redirect(url_for("login"))


# Flask HTTP Basic Auth (for API)

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        "Unauthorized", 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})


def requires_basic_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not user_validate_credentials(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


def flash_form_errors(form):
    for field, errors in form.errors.items():
        for error in errors:
            flash(u"Error in the %s field - %s" % (
                getattr(form, field).label.text,
                error
            ), "error")


# Auth helper functions

# return True is username and password pair match what's in the database
# else return False
def user_validate_credentials(username, password):
    if username not in users:
        return False
    else:
        stored_password = users[username]['password']
        stored_salt = users[username]['salt']
        user_password_hash = hashlib.sha256(str(stored_salt) + password).hexdigest()
        return stored_password == user_password_hash


# return True is password is changed successfully
# else return False
def user_change_credentials(username, password, new_password):
    if username not in users:
        return False
    else:
        # verify current password
        if user_validate_credentials(username, password):
            # change password
            user_password_hash_salt = os.urandom(16).encode("base64")
            user_password_hash = hashlib.sha256(str(user_password_hash_salt) + new_password).hexdigest()
            users[username]["salt"] = user_password_hash_salt
            users[username]["password"] = user_password_hash
            with open("/home/pi/goSecure_Web_GUI/users_db.p", "wb") as fout:
                pickle.dump(users, fout)
            return True
        else:
            return False


# return True if credentials are reset
# else return False
def user_reset_credentials(username, password):
    return user_change_credentials(username, password, "gosecure")


# Routes for web pages

# 404 page
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# Login Page
@app.route("/", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if request.method == "GET":
        return render_template("login.html", form=form) 

    elif request.method == "POST":
        if form.validate():
            username = form.username.data
            password = form.password.data
            if user_validate_credentials(username, password):
                user = User()
                user.id = username
                flask_login.login_user(user)
                
                # check to see if default credentials are being used. If so, redirect to change password page.
                if user_validate_credentials("admin", "gosecure"):
                    flash("Please change the default password.", "notice")
                    return redirect(url_for("user"))
                else:
                    internet_status_bool = internet_status()
                    vpn_status_bool = vpn_status()
                    vpn_configuration_status_bool = vpn_configuration_status()

                    # check to see if network is up. If not, redirect to network page
                    if internet_status_bool is False and vpn_configuration_status_bool is True:
                        flash("Internet is not reachable.", "notice")
                        return redirect(url_for("wifi"))
                    # check to see if network and vpn are up. If not, redirect to initial setup page
                    elif internet_status_bool is False and vpn_status_bool is False:
                        return redirect(url_for("initial_setup"))
                    # check to see if vpn is up. If not, redirect to vpn page
                    elif vpn_status_bool is False:
                        flash("VPN is not established.", "notice")
                        return redirect(url_for("vpn_psk"))
                    else:
                        return redirect(request.args.get("next") or url_for("status"))
            else:
                flash("Invalid username or password. Please try again.", "error")
                return render_template("login.html", form=form)
        else:
            flash_form_errors(form)
            return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    flask_login.logout_user()
    return redirect(url_for("login"))


# User page
@app.route("/status", methods=["GET", "POST"])
@flask_login.login_required
def status():
    form = StatusForm()
    
    if request.method == "GET":
        # check to see if network and vpn are active, red=not active, green=active
        internet_status_color = "green" if internet_status() else "red"
        vpn_status_color = "green" if vpn_status() else "red"
        return render_template("status.html", form=form, internet_status_color=internet_status_color, vpn_status_color=vpn_status_color)


# User page
@app.route("/user", methods=["GET", "POST"])
@flask_login.login_required
def user():
    form = UserForm()
    
    if request.method == "GET":
        form.username.data = flask_login.current_user.id
        return render_template("user.html", form=form)
    
    elif request.method == "POST":
        if form.validate():
            username = form.username.data
            password = form.password.data
            new_password = form.new_password.data
            if user_change_credentials(username, password, new_password):
                flash("Your user information has been successfully changed. Please login with the new credentials.", "success")
                return redirect(url_for("login"))
            else:
                flash("Invalid current username or password. Please try again.", "error")
                return render_template("user.html", form=form)

        else:
            flash_form_errors(form)
            return render_template("user.html", form=form)


# Initial setup page
@app.route("/initial_setup", methods=["GET", "POST"])
@flask_login.login_required
def initial_setup():
    form = InitialSetupForm()

    if request.method == "GET":
        return render_template("initial_setup.html", form=form) 

    elif request.method == "POST":
        if form.validate():
            ssid = form.ssid.data.rsplit("-", 1)[0]
            psk = form.psk.data
            add_wifi(ssid, psk)
            
            if internet_status() is True:
                vpn_server = form.vpn_server.data
                user_id = form.user_id.data
                user_psk = form.user_psk.data
                set_vpn_params(vpn_server, user_id, user_psk)
                restart_vpn()
            
                flash("Wifi and VPN settings saved!", "success")
                return redirect(url_for("status"))
            else:
                flash("Error! Cannot reach the internet...", "error")
                return render_template("initial_setup.html", form=form)
            
        else:
            flash("Error! " + str(form.data), "error")
            return render_template("initial_setup.html", form=form)


# Wifi page
@app.route("/wifi", methods=["GET", "POST"])
@flask_login.login_required
def wifi():
    form = WifiForm()

    if request.method == "GET":
        return render_template("wifi.html", form=form)
    
    elif request.method == "POST":
        if form.validate():
            ssid = form.ssid.data.rsplit("-", 1)[0]
            psk = form.psk.data
            add_wifi(ssid, psk)
            time.sleep(5)
            
            if internet_status() is True:
                restart_vpn()
                time.sleep(5)
                flash("Wifi settings saved! VPN Restarted!", "success")
                return redirect(url_for("status"))
            else:
                flash("Error! Cannot reach the internet...", "error")
                return render_template("wifi.html", form=form)

        else:
            flash("Error! " + str(form.data), "error")
            return render_template("wifi.html", form=form)


# VPN psk page
@app.route("/vpn_psk", methods=["GET", "POST"])
@flask_login.login_required
def vpn_psk():
    form = VpnPskForm()

    if request.method == "GET":
        return render_template("vpn_psk.html", form=form)
    
    elif request.method == "POST":
        if form.validate():
            vpn_server = form.vpn_server.data
            user_id = form.user_id.data
            user_psk = form.user_psk.data
            set_vpn_params(vpn_server, user_id, user_psk)
            restart_vpn()

            if vpn_status():
                flash("VPN settings saved and VPN restarted!", "success")
                return redirect(url_for("status"))
            else:
                flash("VPN settings saved and VPN restarted! Unable to establish VPN connection.", "error")
                return render_template("vpn_psk.html", form=form)
        else:
            flash("Error! " + str(form.data), "error")
            return render_template("vpn_psk.html", form=form)


# Reset to default page
@app.route("/reset_to_default", methods=["GET", "POST"])
@flask_login.login_required
def reset_to_default():
    form = ResetToDefaultForm()

    if request.method == "GET":
        form.username.data = flask_login.current_user.id
        return render_template("reset_to_default.html", form=form)

    elif request.method == "POST":
        if form.validate():
            username = form.username.data
            password = form.password.data
            
            reset_vpn_params()
            reset_wifi()
            
            if user_reset_credentials(username, password):
                flash("Your client has been successfully reset to default settings.", "success")
                return redirect(url_for("logout"))
            else:
                flash("Error resetting client.", "error")
                return render_template("reset_to_default.html", form=form)

        else:
            flash_form_errors(form)
            return render_template("reset_to_default.html", form=form)


@app.route("/action", methods=["POST"])
@flask_login.login_required
def execute_action():
    action = request.form["action"]
    if action == "reboot":
        pi_reboot()
    elif action == "shutdown":
        pi_shutdown()
    elif action == "start_vpn":
        start_vpn()
        flash("VPN Started!", "notice")
    elif action == "stop_vpn":
        stop_vpn()
        flash("VPN Stopped!", "notice")
    elif action == "restart_vpn":
        restart_vpn()
        flash("VPN Restarted!", "notice")
    elif action == "ssh_service":
        start_ssh_service()
        flash("SSH Service Started! It will be turned off on reboot.")
    elif action == "update_client":
        update_client()
        flash("Client will reboot... please reload this page in 1 minute.")
    else:
        form = InitialSetupForm()
        flash("Error! Invalid Action!", "error")
        
    return redirect(url_for("status"))


# REST API
        
@app.route("/v1.0/vpn/credentials", methods=["POST", "DELETE"])
@requires_basic_auth
def api_vpn_credentials():
    if request.method == "POST":
        form = InitialSetupForm()
        form.vpn_server.data = request.json["vpn_server"]
        form.user_id.data = request.json["user_id"]
        form.user_psk.data = request.json["user_psk"]

        if request.headers['Content-Type'] == 'application/json':
            if form.vpn_server.validate(form) and form.user_id.validate(form) and form.user_psk.validate(form):
                set_vpn_params(form.vpn_server.data, form.user_id.data, form.user_psk.data)
                return "Successfully set vpn_server, user_id, and psk for VPN"
            else:
                return "Invalid user_id or psk format"

        else:
            return "415 Unsupported Media Type - Use application/json"

    elif request.method == "DELETE":
        reset_vpn_params()
        return "Successfully reset vpn_server, user_id, and psk for VPN"
    else:
        return "Only POST and DELETE methods are supported. Refer to the API Documentation"


@app.route("/v1.0/vpn/actions", methods=["POST"])
@requires_basic_auth
def api_vpn_actions():
    if request.method == "POST":
        if request.headers['Content-Type'] == 'application/json':
            action = request.json["action"]
            if action == "start_vpn":
                if start_vpn():
                    return "VPN service started, VPN is ESTABLISHED"
                else:
                    return "VPN service started, VPN is NOT ESTABLISHED"
                
            elif action == "stop_vpn":
                stop_vpn()
                return "VPN service stopped, VPN is NOT ESTABLISHED"
            
            elif action == "restart_vpn":
                if restart_vpn():
                    return "VPN service restarted, VPN is ESTABLISHED"
                else:
                    return "VPN service restarted, VPN is NOT ESTABLISHED"
            else:
                return "Error! Invalid Action!"

        else:
            return "415 Unsupported Media Type - Use application/json"
    else:
        return "Only POST method is supported. Refer to the API Documentation"

    
if __name__ == "__main__":
    app.secret_key = os.urandom(24)
    
    # if SSL key and certificate pair do not exist, create them.
    if (os.path.exists("ssl.key") and os.path.exists("ssl.crt")) is not True:
        os.system('openssl genrsa 2048 > ssl.key')
        os.system('openssl req -new -x509 -nodes -sha256 -days 1095 -subj "/C=US/O=goSecure/CN=goSecureClient" -key ssl.key > ssl.crt')
        os.system('sudo chown pi:pi ssl.crt ssl.key')
        os.system('sudo chmod 440 ssl.crt ssl.key')
    
    app.run(host="192.168.50.1", port=443, ssl_context=("ssl.crt", "ssl.key"))
