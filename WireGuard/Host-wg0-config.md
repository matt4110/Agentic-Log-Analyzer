sudo cat /etc/wireguard/wg0.conf
[Interface]
PrivateKey = [Client's Private Key]
Address = [Clients IP on the vpn/24]
[Peer]
PublicKey = [Server's Public Key]
AllowedIPs = [chosen private IP range]
Endpoint = [server's public IP]:41194
PersistentKeepalive = 15