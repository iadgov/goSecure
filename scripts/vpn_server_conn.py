import time
from subprocess import CalledProcessError, check_output
from pi_mgmt import turn_green_led


def set_vpn_params(vpn_server, user_id, user_psk):
    # set the goSecure server IP address in the ipsec.conf file
    with open("/etc/ipsec.conf") as fin:
        lines = fin.readlines()

    for i, line in enumerate(lines):
        current_line = line.strip()
        if current_line.startswith("leftid="):
            lines[i] = "        leftid=%s       # unique id of client\n" % user_id
        elif current_line.startswith("right="):
            lines[i] = "        right=%s       # strongSwan server external IP\n" % vpn_server

    with open("/etc/ipsec.conf", "w") as fout:
        fout.writelines(lines)

    # save the username and secret to the ipsec.secrets file
    with open("/etc/ipsec.secrets", "w") as secrets:
        secrets.write("%s : PSK %s" % (user_id, user_psk))


def reset_vpn_params():
    set_vpn_params("<eth0_ip_of_server>",
                   "<unique_id_of_client>",
                   "<password_for_client>")
    stop_vpn()


def add_route():
    """ Add route for accessing local ip addresses on the LAN interface
    (prevents getting locked out from the goSecure Client web gui)
    """

    route_table_list = check_output(["ip", "route", "show", "table", "220"]).split("\n")

    if "192.168.50.0/24 dev eth0  scope link" not in route_table_list:
        try:
            check_output(["sudo", "ip", "route", "add", "table", "220", "192.168.50.0/24", "dev", "eth0"])
        except CalledProcessError:
            return False
    return True


def start_vpn():
    try:
        check_output(["sudo", "ipsec", "start"])
    except CalledProcessError:
        return False
    else:
        time.sleep(10)

    if vpn_status() and add_route():
        time.sleep(3)
        turn_green_led(on=True)
        return True
    else:
        return False


def stop_vpn():
    try:
        check_output(["sudo", "ipsec", "stop"])
    except CalledProcessError:
        return False
    else:
        turn_green_led(on=False)
        return True


def restart_vpn():
    turn_green_led(on=False)

    try:
        check_output(["sudo", "ipsec", "restart"])
    except CalledProcessError:
        return False
    else:
        time.sleep(10)

    if vpn_status() and add_route():
        time.sleep(3)
        turn_green_led(on=True)
        return True
    else:
        return False


def vpn_status():
    try:
        vpn_status_info = check_output(["sudo", "ipsec", "status"]).split("\n")
    except CalledProcessError:
        return False
    else:
        # ipsec status command ran successfully, check if tunnel is established
        return vpn_status_info[1].strip()[9:20] == "ESTABLISHED"


def vpn_configuration_status():
    leftid_set = 0  # unique id of client
    right_set = 0  # strongSwan server external IP or DNS name
    vpn_psk = 0  # unique id of client and psk for VPN

    # check to see if the leftid, and right are set in the ipsec.conf file
    with open("/etc/ipsec.conf") as fin:
        lines = fin.readlines()

    for line in lines:
        current_line = line.strip()
        if (current_line.startswith("leftid=") and
                not current_line.startswith("leftid=<unique_id_of_client>")):
            leftid_set = 1
        elif (current_line.startswith("right=") and
              not current_line.startswith("right=<eth0_ip_of_server>")):
            right_set = 1

    # check if the username and secret are set in the ipsec.secrets file
    with open("/etc/ipsec.secrets") as fin:
        first_line = next(fin).strip()

    if not first_line.startswith(
            "<unique_id_of_client> : PSK <password_for_client>"):
        vpn_psk = 1

    return leftid_set == 1 and right_set == 1 and vpn_psk == 1
