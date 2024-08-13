#!/usr/bin/env python3

import argparse
import configparser
import ipaddress
import os
import logging
import re
import subprocess

WG_INTERFACE = 'wg0'
WG_CONF_FILE = '/etc/wireguard/wg0.conf'
WG_CLIENT_DIR = '/etc/wireguard/clients'
WGMANAGER_CONF = '/etc/wireguard/wgmanager.conf'

def generate_wg_keys():
    private_key = subprocess.check_output("wg genkey", shell=True).decode("utf-8").strip()
    public_key = subprocess.check_output(f"echo '{private_key}' | wg pubkey", shell=True).decode("utf-8").strip()
    preshared_key = subprocess.check_output("wg genpsk", shell=True).decode("utf-8").strip()
    return (private_key, public_key, preshared_key)

def get_private_key_from_wg_conf():
    with open(WG_CONF_FILE, 'r') as file:
        for line in file:
            if line.startswith('PrivateKey'):
                private_key = line.split('=', 1)[1].strip()
                return private_key
            
    raise ValueError(f"PrivateKey not found in {WG_CONF_FILE}") 

def get_network_from_wg_conf():
    with open(WG_CONF_FILE, 'r') as file:
        for line in file:
            if line.startswith('Address'):
                network_str = line.split('=')[1].strip()
                network = ipaddress.ip_network(network_str, strict=False)
                return network

    raise ValueError(f"Address not found in {WG_CONF_FILE}")

def get_port_from_wg_conf():
    with open(WG_CONF_FILE, 'r') as file:
        for line in file:
            if line.startswith('ListenPort'):
                port= line.split('=')[1].strip()
                return port

    raise ValueError(f"ListenPort not found in {WG_CONF_FILE}")

def get_public_key_from_private(private_key):
    public_key = subprocess.check_output(f"echo '{private_key}' | wg pubkey", shell=True).decode("utf-8").strip()
    return public_key

def get_used_ips():
    config = configparser.ConfigParser()
    config.read(WGMANAGER_CONF)

    used_ips = set()
    for section in config.sections():
        if section == 'wgmanager':
            continue
        used_ips.add(config.get(section, 'ip'))

    return used_ips

def find_free_ips(network, used_ips):
    ips = []

    for ip in network.hosts():
        if str(ip).endswith('.1') or str(ip).endswith('.255'):
            continue
        if str(ip) not in used_ips:
            ips.append(str(ip))

    return ips

def get_valid_domain_or_ip(prompt):
    while True:
        input_str = input(prompt).strip()
        if validate_ip(input_str) or validate_domain(input_str):
            return input_str
        else:
            logging.error("Invalid IP address or domain name")

def get_valid_ip_or_empty(prompt):
    while True:
        ip_str = input(prompt).strip()
        if validate_ip(ip_str):
            return ip_str
        elif ip_str == "":
            return None
        else:
            logging.error(f"IP address {ip_str} is invalid")
        
def get_allowed_ip_or_empty(prompt):
    while True:
        ips_str = input(prompt).strip()
        if ips_str == "":
            return None
        elif validate_allowed_ips(ips_str):
            ips_str.replace(' ', '')
            return ips_str

def process_dns_servers(dns_server1, dns_server2):
    if dns_server1 == None:
        dns_server1 = "8.8.8.8"

    if dns_server1 == dns_server2:
        return dns_server1

    if dns_server2 != None:
        return f"{dns_server1},{dns_server2}"
    else:
        return dns_server1

def validate_domain(domain_str):
    domain_regex = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")
    if domain_regex.match(domain_str):
        return True
    
    return False

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_ip_array(ip_list_str):
    ips = [ip.strip() for ip in ip_list_str.split(',')]
    return all(validate_ip(ip) for ip in ips)

def check_name_avail(name):
    config = configparser.ConfigParser()
    config.read(WGMANAGER_CONF)

    if config.has_section(name):
        logging.error(f"Client with name {name} already exist")
        return False
    return True

def validate_name(name):
    if bool(re.match(r'^[A-Za-z0-9_-]+$', name)):
        return True
    else:
        logging.error("Name must contain only letters, digits, underscores and dashes")
        return False 

def validate_port(port):
    if 65535 > int(port) > 0:
        return True
    return False

def validate_allowed_ips(allowed_ips_str):
    allowed_ips = [ip.strip() for ip in allowed_ips_str.split(',')]
    
    for ip in allowed_ips:
        try:
            ipaddress.ip_network(ip, strict=False)
        except ValueError:
            logging.error(f"Invalid IP address or subnet: {ip}")
            return False
    
    return True

def manager_setup():
    config = configparser.ConfigParser()
    config.read(WGMANAGER_CONF)

    server_addr = get_valid_domain_or_ip("Enter server IP or domain name: ")
    dns_server1 = get_valid_ip_or_empty("Enter the DNS server IP (default: 8.8.8.8): ")
    dns_server2 = get_valid_ip_or_empty("Enter the additional DNS server IP (optional): ")
    server_port = get_port_from_wg_conf()
    server_public_key = get_public_key_from_private(get_private_key_from_wg_conf())

    dns_servers = process_dns_servers(dns_server1, dns_server2)

    config.remove_section('wgmanager')
    config.add_section('wgmanager')
    config.set('wgmanager', 'server_public_key', server_public_key)
    config.set('wgmanager', 'server_addr', server_addr)
    config.set('wgmanager', 'server_port', server_port)
    config.set('wgmanager', 'dns_servers', dns_servers)

    with open(WGMANAGER_CONF, 'w') as configfile:
        config.write(configfile)

def is_config_valid():
    """
    check if wgmanager config valid
    """
    if not os.path.exists(WG_CLIENT_DIR):
        os.makedirs(WG_CLIENT_DIR)

    if not os.path.exists(WGMANAGER_CONF):
        logging.error(f"File {WGMANAGER_CONF} does not exist")
        return False
    
    config = configparser.ConfigParser()
    config.read(WGMANAGER_CONF)

    if 'wgmanager' not in config.sections():
        logging.error(f"Section [wgmanager] not found in {WGMANAGER_CONF}")
        return False
    
    server_addr = config['wgmanager'].get('server_addr')
    if not server_addr:
        logging.error('Field server_addr is empty')
        return False
    
    server_port = config['wgmanager'].get('server_port')
    if not server_port or not validate_port(server_port):
        logging.error('Field server_port is empty or contains invalid port')
        return False
    
    server_public_key = config['wgmanager'].get('server_public_key')
    if not server_public_key:
        logging.error('Field server_public_key is empty')
        return False

    dns_servers = config['wgmanager'].get('dns_servers')
    if not dns_servers or not validate_ip_array(dns_servers):
        logging.error('Field dns_servers is empty or contains invalid IP')
        return False

    logging.info('Wgmanager config valid.')
    return True

def config_cleanup():
    config = configparser.ConfigParser()
    config.read(WGMANAGER_CONF)

    for section in config.sections():
        if section == 'wgmanager':
            continue

        if not config.has_option(section, 'ip') or not config.has_option(section, 'public_key') or not config.has_option(section, 'private_key'):
            logging.warning(f"Section {section} is invalid. Removing...")
            config.remove_section(section)
    
    with open(WGMANAGER_CONF, 'w') as configfile:
        config.write(configfile)

def check_requirements():
    if subprocess.call('which wg', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        logging.error("wg not found")
        return False
    
    if subprocess.call('which wg-quick', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        logging.error("wg-tool not found")
        return False

    if os.geteuid() != 0:
        logging.error("This script must be run as root")
        return False
    
    return True

def generate_user_config(name, client_ip, private_key, preshared_key, allowed_ips):
    config = configparser.ConfigParser()
    config.read(WGMANAGER_CONF)
    server_addr = config.get('wgmanager', 'server_addr')
    server_port = config.get('wgmanager', 'server_port')
    server_public_key  = config.get('wgmanager', 'server_public_key')
    dns_servers = config.get('wgmanager', 'dns_servers')

    client_config = configparser.ConfigParser()
    client_config.add_section('Interface')
    client_config.set('Interface', 'PrivateKey', private_key)
    client_config.set('Interface', 'Address', f"{client_ip}/32")
    client_config.set('Interface', 'DNS', dns_servers)

    client_config.add_section('Peer')
    client_config.set('Peer', 'PublicKey', server_public_key)
    client_config.set('Peer', 'PresharedKey', preshared_key)
    client_config.set('Peer', 'Endpoint', f"{server_addr}:{server_port}")
    client_config.set('Peer', 'AllowedIPs', allowed_ips)

    with open(f"{WG_CLIENT_DIR}/{name}.conf", 'w+') as configfile:
        client_config.write(configfile)


    print()
    try:
        qr = subprocess.check_output(f"qrencode {WG_CLIENT_DIR}/{name}.conf -t UTF8", shell=True).decode("utf-8").strip()
        print(qr)
    except:
        logging.error('Cannot create QR code. Check if qrencode installed')
    logging.info(f"Config saved to {WG_CLIENT_DIR}/{name}.conf")
    print()

def list_users():
    config = configparser.ConfigParser()
    config.read(WGMANAGER_CONF)

    for section in config.sections():
        if section == 'wgmanager':
            continue

        print(f" - {section} [{config.get(section, 'ip')}]")

def add_peer(client_ip, public_key):
    try:
        _ = subprocess.check_output(f"wg set {WG_INTERFACE} peer '{public_key}' allowed-ips {client_ip}/32", shell=True)
        return True
    except:
        return False

def add_user(name, allowed_ips, ip=None):
    config = configparser.ConfigParser()
    config.read(WGMANAGER_CONF)

    used_ips = get_used_ips()
    network = get_network_from_wg_conf()
    free_ips = find_free_ips(network, used_ips)

    if config.has_section(name):
        logging.error(f"Client with name {name} already exist")
        return False

    if ip:
        if not validate_ip(ip):
            logging.error(f"Address {ip} is invalid")
            return False

        if ip in free_ips:
            client_ip = ip
        else:
            logging.error(f"Address {ip} already in use")
            return False
    else:
        client_ip = free_ips[0]

    private_key, public_key, preshared_key = generate_wg_keys()

    config.add_section(name)
    config.set(name, 'ip', client_ip)
    config.set(name, 'public_key', public_key)
    config.set(name, 'private_key', private_key)
    config.set(name, 'preshared_key', preshared_key)
    config.set(name, 'allowed_ips', allowed_ips)

    if not add_peer(client_ip, public_key):
        return False

    generate_user_config(name, client_ip, private_key, preshared_key, allowed_ips)

    with open(WGMANAGER_CONF, 'w') as configfile:
        config.write(configfile)

    return True

def remove_user(name):
    config = configparser.ConfigParser()
    config.read(WGMANAGER_CONF)

    if not config.has_section(name):
        logging.error("User does not exist")
        return False
    
    config.remove_section(name)

    with open(WGMANAGER_CONF, 'w') as configfile:
        config.write(configfile)

    return True

def sync_conf_with_wg():
    config = configparser.ConfigParser()
    config.read(WGMANAGER_CONF)

    # find all peers
    out = subprocess.check_output("wg show", shell=True).decode("utf-8")
    peers = re.findall(r"peer:\s(.+)", out)

    clients = []
    for section in config.sections():
        if section == 'wgmanager':
            continue

        client_key = config.get(section, 'public_key')
        clients.append(client_key)
        if client_key not in peers:
            cmd = f"wg set {WG_INTERFACE} peer '{client_key}' allowed-ips {config.get(section, 'ip')}/32"
            subprocess.run(cmd, shell=True)

    for peer in peers:
        if peer not in clients:
            cmd = f"wg set {WG_INTERFACE} peer '{peer}' remove"
            subprocess.run(cmd, shell=True)

    cmd = f"wg-quick save {WG_INTERFACE}"
    subprocess.run(cmd, shell=True)

def main():
    parser = argparse.ArgumentParser(description='WireGuard client manager')
    parser.add_argument('--list', action='store_true', help='list clients')
    parser.add_argument('--add', metavar='NAME', help='add new client')
    parser.add_argument('--remove', metavar='NAME', help='remove an existing client')
    parser.add_argument('--setup', action='store_true', help='start manager setup process')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose output')
    args = parser.parse_args()

    # setup logger
    logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.INFO)
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not check_requirements():
        exit(1)

    # check if config valid
    if not is_config_valid():
        manager_setup()
    
    # remove unmanaged entries
    config_cleanup()

    if args.list:
        list_users()
    elif args.add:
        name = args.add
        if not validate_name(name):
            exit(1)

        if not check_name_avail(name):
            exit(1)

        ip = get_valid_ip_or_empty(f"Enter IP for client or leave empty to autogenerate ({get_network_from_wg_conf()}): ")

        allowed_ips = get_allowed_ip_or_empty("Enter allowed IPs (default - 0.0.0.0/0): ")
        if allowed_ips == None:
            allowed_ips = "0.0.0.0/0"

        if add_user(name, allowed_ips, ip):
            sync_conf_with_wg()
        else:
            exit(1)

    elif args.remove:
        name = args.remove
        if not validate_name(name):
            exit(1)

        if remove_user(args.remove):
            sync_conf_with_wg()
        else:
            exit(1)
    elif args.setup:
        manager_setup()
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
