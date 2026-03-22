[Interface]
Address = [Server IP in VPN]/24
ListenPort = 41194
PrivateKey = [Server Private Key]

[Peer]
PublicKey = [Client Public Key]
AllowedIPs = [Client IP in VPN]/32 #This creates a split tunnel