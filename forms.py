from flask.ext.wtf import Form
from wtforms import (
    PasswordField, SelectField, SubmitField, StringField, validators)

from scripts.rpi_network_conn import get_wifi_list


class LoginForm(Form):
    username = StringField("Username", [
        validators.DataRequired("Please enter the username."),
        validators.Length(
            min=2,
            max=25,
            message="Please enter a username between 2 and 25 characters.")
    ])
    password = PasswordField("Password", [
        validators.DataRequired("Please enter the password."),
        validators.Length(
            min=8,
            max=128,
            message="Please enter a password between 8 and 128 characters.")
    ])
    login_submit = SubmitField("Login", [validators.DataRequired()])


class StatusForm(Form):
    pass


class UserForm(Form):
    username = StringField("Username", [
        validators.DataRequired("Please enter the username."),
        validators.Length(
            min=2,
            max=25,
            message="Please enter a username between 2 and 25 characters.")
    ])
    password = PasswordField("Current Password", [
        validators.DataRequired("Please enter the password."),
        validators.Length(
            min=8,
            max=128,
            message="Please enter a password between 8 and 128 characters.")
    ])
    new_password = PasswordField("New Password", [
        validators.DataRequired("Please enter a new password."),
        validators.Length(
            min=8,
            max=128,
            message="Please enter a new password between 8 and 128 characters."),
        validators.EqualTo('confirm_password', message='Passwords must match')
    ])
    confirm_password = PasswordField("Repeat New Password")
    user_submit = SubmitField("Save and Logout", [validators.DataRequired()])


class ResetToDefaultForm(Form):
    username = StringField("Username", [
        validators.DataRequired("Please enter the username."),
        validators.Length(
            min=2,
            max=25,
            message="Please enter a username between 2 and 25 characters.")
    ])
    password = PasswordField("Current Password", [
        validators.DataRequired("Please enter the password."),
        validators.Length(
            min=8,
            max=128,
            message="Please enter a password between 8 and 128 characters.")
    ])
    reset_to_default_submit = SubmitField("Reset and Logout", [validators.DataRequired()])


class WifiForm(Form):
    wifi_list = get_wifi_list()
    ssid = SelectField("Network Name", choices=wifi_list)
    # ssid = SelectField("Network Name", choices=[("Wifi 1","Wifi 1"),("Wifi 2", "Wifi 2")])
    psk = PasswordField("Password", [validators.DataRequired()])
    wifi_submit = SubmitField("Save", [validators.DataRequired()])


class VpnPskForm(Form):
    vpn_server = StringField("Server Hostname", [
        validators.DataRequired("Please enter the goSecure Server Hostname or IP Address."),
        validators.Length(
            max=255,
            message="Please enter a goSecure Server Hostname or IP Address between 0 and 255 characters.")
    ])
    user_id = StringField("VPN User ID", [
        validators.DataRequired("Please enter the goSecure User Id."),
        validators.Length(
            max=255,
            message="Please enter a goSecure User Id between 0 and 255 characters.")
    ])
    user_psk = PasswordField("VPN PSK", [
        validators.DataRequired(),
        validators.Length(
            min=16,
            max=255,
            message="Please enter a goSecure User PSK between 16 and 255 characters.")
    ])
    vpn_psk_submit = SubmitField("Save", [validators.DataRequired()])


class InitialSetupForm(Form):
    wifi_list = get_wifi_list()
    ssid = SelectField("Network Name", choices=wifi_list)
    # ssid = SelectField("Network Name", choices=[("Wifi 1","Wifi 1"),("Wifi 2", "Wifi 2")])
    psk = PasswordField("Password", [validators.DataRequired()])

    vpn_server = StringField("Server Hostname", [
        validators.DataRequired("Please enter the goSecure Server Hostname or IP Address."),
        validators.Length(
            max=255,
            message="Please enter a goSecure Server Hostname or IP Address between 0 and 255 characters.")
    ])
    user_id = StringField("VPN User ID", [
        validators.DataRequired("Please enter the goSecure User Id."),
        validators.Length(
            max=255,
            message="Please enter a goSecure User Id between 0 and 255 characters.")
    ])
    user_psk = PasswordField("VPN PSK", [
        validators.DataRequired(),
        validators.Length(
            min=16,
            max=255,
            message="Please enter a goSecure User PSK between 16 and 255 characters.")
    ])
    initial_setup_submit = SubmitField("Save", [validators.DataRequired()])
