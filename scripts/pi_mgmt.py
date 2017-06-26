import os
import textwrap
from subprocess import call

import RPi.GPIO as GPIO


def pi_reboot():
    os.system("sudo reboot")


def pi_shutdown():
    os.system("sudo shutdown -h now")


def start_ssh_service():
    os.system("sudo service ssh start")


def update_client():
    update_user_interface_commands = textwrap.dedent("""\
        sudo mv /home/pi/goSecure_Web_GUI /home/pi/goSecure_Web_GUI.old
        wget -P /home/pi/. https://github.com/iadgov/goSecure/archive/master.zip
        unzip -d /home/pi/. /home/pi/master.zip
        rm /home/pi/master.zip
        sudo mv /home/pi/goSecure-master /home/pi/goSecure_Web_GUI
        sudo mv /home/pi/goSecure_Web_GUI.old/ssl.crt /home/pi/goSecure_Web_GUI/.
        sudo mv /home/pi/goSecure_Web_GUI.old/ssl.key /home/pi/goSecure_Web_GUI/.
        sudo mv /home/pi/goSecure_Web_GUI.old/users_db.p /home/pi/goSecure_Web_GUI/.
        sudo chown -R pi:pi /home/pi/goSecure_Web_GUI
        sudo find /home/pi/goSecure_Web_GUI -type d -exec chmod 550 {} \;
        sudo find /home/pi/goSecure_Web_GUI -type f -exec chmod 440 {} \;
        sudo chmod 660 /home/pi/goSecure_Web_GUI/users_db.p
        sudo reboot""")

    for command in update_user_interface_commands.splitlines():
        call(command, shell=True)


def turn_green_led(on=True):
    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    GPIO.setup(7, GPIO.OUT)
    GPIO.output(7, GPIO.HIGH if on else GPIO.LOW)
