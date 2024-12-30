import os
import re
import subprocess

def is_valid_client_name(name):
    return re.match(r'^[a-zA-Z0-9_-]+$', name)

def get_client_name():
    while True:
        client = input("Client name: ")
        if is_valid_client_name(client):
            return client

def get_password_choice():
    while True:
        choice = input("Select an option [1-2]: ")
        if choice in ['1', '2']:
            return choice

def client_exists(client):
    result = subprocess.run(
        ["grep", "-c", f"/CN={client}$", "/etc/openvpn/easy-rsa/pki/index.txt"],
        stdout=subprocess.PIPE,
        text=True
    )
    return result.stdout.strip() == '1'

def build_client(client, choice):
    os.environ['EASYRSA_CERT_EXPIRE'] = '3650'
    command = ["./easyrsa", "--batch", "build-client-full", client]
    if choice == '1':
        command.append("nopass")
    subprocess.run(command)

def get_home_directory(client):
    if os.path.exists(f"/home/{client}"):
        return f"/home/{client}"
    sudo_user = os.getenv("SUDO_USER", "root")
    return f"/home/{sudo_user}" if sudo_user != "root" else "/root"

def get_tls_signature():
    with open("/etc/openvpn/server.conf") as f:
        for line in f:
            if line.startswith("tls-crypt"):
                return "1"
            elif line.startswith("tls-auth"):
                return "2"
    return None

def write_client_config(client, home_dir, tls_sig):
    with open(f"/etc/openvpn/client-template.txt") as template_file:
        config_content = template_file.read()

    with open(f"{home_dir}/{client}.ovpn", "w") as client_config:
        client_config.write(config_content)
        for section in [("ca", "/etc/openvpn/easy-rsa/pki/ca.crt"),
                        ("cert", f"/etc/openvpn/easy-rsa/pki/issued/{client}.crt"),
                        ("key", f"/etc/openvpn/easy-rsa/pki/private/{client}.key")]:
            client_config.write(f"<{section[0]}>\n")
            with open(section[1]) as section_file:
                client_config.write(section_file.read())
            client_config.write(f"</{section[0]}>\n")

        if tls_sig == '1':
            client_config.write("<tls-crypt>\n")
            with open("/etc/openvpn/tls-crypt.key") as tls_crypt_file:
                client_config.write(tls_crypt_file.read())
            client_config.write("</tls-crypt>\n")
        elif tls_sig == '2':
            client_config.write("key-direction 1\n<tls-auth>\n")
            with open("/etc/openvpn/tls-auth.key") as tls_auth_file:
                client_config.write(tls_auth_file.read())
            client_config.write("</tls-auth>\n")

def new_client():
    print("\nTell me a name for the client.")
    client = get_client_name()

    print("\nDo you want to protect the configuration file with a password?")
    print("   1) Add a passwordless client")
    print("   2) Use a password for the client")
    choice = get_password_choice()

    if client_exists(client):
        print("\nThe specified client CN was already found in easy-rsa, please choose another name.")
        return

    build_client(client, choice)
    print(f"Client {client} added.")

    home_dir = get_home_directory(client)
    tls_sig = get_tls_signature()
    write_client_config(client, home_dir, tls_sig)

    print(f"\nThe configuration file has been written to {home_dir}/{client}.ovpn.")
    print("Download the .ovpn file and import it in your OpenVPN client.")

if __name__ == "__main__":
    new_client()
