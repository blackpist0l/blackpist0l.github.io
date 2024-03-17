---
layout: post
title: Setup Wireguard VPN
date: 2024-03-17 16:08 -0600
categories: Tools
tags: Wireguard VPN
image:
    path: /assets/img/headers/your-own-wireguard-vpn.png
    alt: Wireguard VPN
---

Holaa! Joven informático, hace tiempo empecé a divagar por el mundo de la VPNs para uso personal, nada el otro mundo, pensé en adquirir alguna por medio de algún proveedor, como:

- [ufovpn](https://que-no.com)

No mentira, aun con múltiples proveedores y agradable precio, decidí montar mi propio servicio VPN en un VPS con wireguard y dnscrypt-proxy. Es por eso el motivo de este post, ya que hice un [script](https://github.com/JuanVazquez-REM/setup-wireguard-vpn) simple, para agilizar un poco el proceso, así que humildemente se lo comparto.

```bash
#!/bin/bash

#Global variables
name_client=""
#exist=true

function ctrl_c(){
    echo -e "\n[*] Canceling script...\n"
    exit 1
}
trap ctrl_c INT

function is_root() {
	if [ "$EUID" -ne 0 ]; then
        echo -e "\n[*] Must run with root"
		exit 1
	fi
}

is_root # checf if root

function setup_wireguard(){
    echo -e "\n[*] Setup Wireguard in progress"
    update_system

    #install and set permissions at folder
    apt-get install wireguard iptables net-tools -y
    umask 077 /etc/wireguard

    
    echo -ne "\n[*] Name VPN: " 
    read -r name_vpn

    echo -e "\n ----- Available network interface -----\n"
        ip addr | grep UP | awk '{print $2}' FS=':' | tail -n +2 
    echo -ne "\n [*] Output interface to use? (ex. enp0s3): "
    read -r interface

    echo -ne "\n [*] VPN Server IP? (ex. 208.74.151.7): "
    read -r server_ip

    file_key_priv="$name_vpn"_server_priv
    file_key_pub="$name_vpn"_server_pub
    file_server="$name_vpn".conf

    # generate keys
    wg genkey | tee "$file_key_priv" | wg pubkey > "$file_key_pub"


    # config file server
    {   
        echo "#server_ip $server_ip"
        echo "[Interface]" 
        echo "PrivateKey = $(cat "$file_key_priv")"
        echo "Address = 10.0.0.1/32"
        echo "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $interface -j MASQUERADE"
        echo "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $interface -j MASQUERADE"
        echo "ListenPort = 51820"
    } >> "$file_server"

    # enable packet forwarding
    sysctl -w net.ipv4.ip_forward=1
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

    # move files
    mv "$file_server" /etc/wireguard/
    mv "$name_vpn"_server_priv "$name_vpn"_server_pub /etc/wireguard/

    # start and enable service
    systemctl enable wg-quick@"$name_vpn"
    systemctl start wg-quick@"$name_vpn"

    echo -e "\n[*] Wireguard Installed"
}

function new_vpn_client(){
    echo -e "\n[*] New client in progress"

    echo -ne "\n [*] Name client (optional): "
    read -r name_client;

    name_vpn_file=$(basename /etc/wireguard/*.conf | awk '{print $1}' FS='.')

    #Generate keys
    number_client="$(grep -wc "Peer" < /etc/wireguard/"$name_vpn_file".conf)"
    wg genkey | tee "$number_client$name_client"_client_priv | wg pubkey > "$number_client$name_client"_client_pub

    #ip client
    echo -e "\n [!] The IP must be in range $(grep -nw "Address" < /etc/wireguard/"$name_vpn_file".conf | awk '{print $3}' | sed 's/\/32$/\/24/' |  sed 's/\.1\//.0\//') | IP 10.0.0.1 was reserved for the server"
    echo -n "[*] Client Private IP: "
    read -r ip_client

    #insert to file vpn
    {   
        echo -e "\n #client: $name_client"
        echo "[Peer]"
        echo "PublicKey = $(cat "$number_client$name_client"_client_pub)"
        echo "AllowedIPs = $ip_client/32"
    } >> "/etc/wireguard/$name_vpn_file.conf"

    echo -e "\n[*] Configuration Completed on the Server"
    echo "[!] Download wireguard-tools on your client" 
    echo "[!] This is your client file"
    
    #values of vpn file
    ip_public_server=$(grep -nw "server_ip" < "/etc/wireguard/$name_vpn_file.conf" | awk '{print $2}')
    ip_port_vpn=$(grep -nw "ListenPort" < "/etc/wireguard/$name_vpn_file.conf" | awk '{print $2}' FS='=' | tr -d ' ')

    #values file client
    echo -e "\n ------------------------------------------------------------"
    echo "[Interface]"
    echo "PrivateKey = $(cat "$number_client$name_client"_client_priv)" 
    echo -e "Address = $ip_client/32\n" 

    echo "[Peer]" 
    echo "PublicKey = $(cat "/etc/wireguard/$name_vpn_file"_server_pub)" 
    echo "AllowedIPs = 0.0.0.0/0" 
    echo "Endpoint = $ip_public_server:$ip_port_vpn"
    echo "PersistentKeepalive = 25"
    echo -e "\n ------------------------------------------------------------"

    #mv keys client
    mv "$number_client$name_client"_client_priv "$number_client$name_client"_client_pub /etc/wireguard

    #restart service
    systemctl restart "wg-quick@$name_vpn_file.service"
    
    echo -e "\n[*] New Registered Client"
}


function setup_dnscrypt(){
    echo -e "\n[*] Setup Dnscrypt-proxy in progress"
    update_system
    disable_ipv6

    apt-get install dnscrypt-proxy -y
    systemctl enable dnscrypt-proxy
    systemctl start dnscrypt-proxy
    systemctl status dnscrypt-proxy | grep active

    echo "nameserver 127.0.2.1" > /etc/resolv.conf
    chmod 644 /etc/resolv.conf
    chattr +i /etc/resolv.conf

    echo -e "\n[*] Dnscrypt-proxy Installed"
}

function disable_ipv6(){
    echo -e "\n[*] Disable IPv6"

    line_disable_ipv6="net.ipv6.conf.all.disable_ipv6 = 1"
    line_default_disable_ipv6="net.ipv6.conf.default.disable_ipv6 = 1"
    match="$(grep -wc "$line_disable_ipv6\|$line_default_disable_ipv6" < /etc/sysctl.conf)"

    #is disable?
    if [[ match -eq 0 ]]; then
        echo "$line_disable_ipv6" >> /etc/sysctl.conf
        echo "$line_default_disable_ipv6" >> /etc/sysctl.conf
        sysctl -p
        systemctl restart NetworkManager
    fi

    echo -e "\n[*] IPv6 was disabled"
}

function update_system(){
    echo -e "\n[*] Updating repository list"

    #the testing repo is added?
    repo_testing="deb https://deb.debian.org/debian/ testing main"
    search_repo_testing=$(grep -wc "$repo_testing" < /etc/apt/sources.list)
    if [[ $search_repo_testing -eq 0 ]];then
        echo -e "\n[*] Add repo testing main"
        echo "$repo_testing" >> /etc/apt/sources.list
    fi
    
    apt-get update
    apt install "linux-headers-$(uname -r)" -y

    # the /usr/sbin is added?
    if [[ $(echo "$PATH" | grep -cwn "/usr/sbin") -eq 0 ]] ;then
        echo -e "\n[*] Add /usr/sbin to PATH"
        echo "export PATH='/usr/sbin:$PATH'" >> ~/.bashrc
        # shellcheck source=/dev/null
        source ~/.bashrc
    fi
    
    echo -e "\n[*] Finished updating the repositories"
}

function install_all(){
    setup_wireguard
    setup_dnscrypt
    new_vpn_client
}

while true; do
    echo -e "------ Welcome to WireguardVPN -----\n"
    echo "1) Install All"
    echo "2) Install WireguardVPN"
    echo "3) Install Dnscrypt-proxy"
    echo "4) New VPN Client"
    echo "0) Exit"

    echo -n "Option: "
    read -r option


    case "${option}" in
        1) install_all;;
        2) setup_wireguard;;
        3) setup_dnscrypt;;
        4) new_vpn_client;;
        *) exit 0;;
    esac
    
done
```

Te dejo este [material](https://www.youtube.com/watch?v=8bAf8HDYyhM&ab_channel=ZKCiberseguridad) meramente informativo, que me ayudó a entender este acto de montar tu propio servicio VPN y cómo funciona.  

Hasta aquí mi reporte joven lector, con su permiso, me retiro 🙂.

![](/assets/img/posts/979d76c5c386fe467133210d3972634d.gif)


