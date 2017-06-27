import textwrap
import time
import urllib2
from subprocess import CalledProcessError, check_output, Popen

import wifi_captive_portal


def get_wifi_list():
    # check wlan status, return [] if no wifi available
    try:
        check_output(["sudo", "ifup", "wlan0"])
    except CalledProcessError:
        return []

    # check for wifi access points in range, return [] if none available
    try:
        iw_list = check_output(["sudo", "iwlist", "wlan0", "scan"]).split("\n")
    except CalledProcessError:
        return []

    # contains a tuple of the (ESSID, Encryption key)
    wifi_list = []

    for i, interface_info in enumerate(iw_list):
        current = interface_info.strip()
        if current.startswith("ESSID"):
            end = current[7:-1]
            if end and (not end.startswith("\\")):
                wifi_list.append(
                    ('%s-%s' % (end, iw_list[i - 1].strip()[15:]), end))

    return sorted(set(wifi_list), key=lambda wifilist: wifilist[0])


def add_wifi(wifi_ssid, wifi_key):
    ssid = 'ssid="%s"' % wifi_ssid

    if wifi_key == "key_mgmt_none":
        wifi_key_info = "    key_mgmt=NONE\n"
    else:
        wifi_key_info = '    psk="%s"\n' % wifi_key

    with open("/etc/wpa_supplicant/wpa_supplicant.conf") as wpa_supplicant:
        lines = wpa_supplicant.readlines()

    wifi_exists = False
    for i in xrange(len(lines)):
        # if SSID is already in file
        if lines[i].strip() == ssid:
            wifi_exists = True
            lines[i] = "    %s\n" % ssid
            lines[i + 1] = wifi_key_info

    if not wifi_exists:
        lines.append(textwrap.dedent("""\
            network={
                %s
                %s
            }
            """ % (ssid, wifi_key_info)))

    with open("/etc/wpa_supplicant/wpa_supplicant.conf", "w") as fout:
        fout.writelines(lines)

    process = Popen(["sudo", "ifdown", "wlan0"])
    process.wait()
    process = Popen(["sudo", "ifup", "wlan0"])
    process.wait()

    time.sleep(15)

    if not internet_status():
        wifi_captive_portal.captive_portal(wifi_ssid, "", "")


def internet_status():
    try:
        urllib2.urlopen("https://aws.amazon.com", timeout=1)
    except urllib2.URLError:
        return False
    else:
        return True


def reset_wifi():
    lines = textwrap.dedent("""\
        country=US
        ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
        update_config=1
        """)
    with open("/etc/wpa_supplicant/wpa_supplicant.conf", "w") as fout:
        fout.write(lines)

    try:
        check_output(["sudo", "ifdown", "wlan0"])
    except CalledProcessError:
        return False
    else:
        return True
