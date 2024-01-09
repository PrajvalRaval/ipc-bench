sudo ip tuntap del tun0 mode tun
sudo ip tuntap add name tun0 mode tun user $USER
sudo ip link set tun0 up
sudo ip addr add 192.0.2.1 peer 192.0.2.2 dev tun0

sudo ip tuntap del tun1 mode tun
sudo ip tuntap add name tun1 mode tun user $USER
sudo ip link set tun1 up
sudo ip addr add 192.0.3.1 peer 192.0.3.2 dev tun1

sudo iptables -A FORWARD -i tun0 -s 192.0.2.2 -j ACCEPT
sudo iptables -A FORWARD -i tun1 -s 192.0.3.2 -j ACCEPT

sudo iptables -A FORWARD -o tun0 -d 192.0.2.2 -j ACCEPT
sudo iptables -A FORWARD -o tun1 -d 192.0.3.2 -j ACCEPT

sudo sysctl -w net.ipv4.ip_forward=1


# sudo iptables -A INPUT -i tun1 -m state --state RELATED,ESTABLISHED -j ACCEPT
# sudo iptables -A INPUT -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# sudo sysctl net.ipv4.conf.tun0.accept_local=1
# sudo sysctl net.ipv4.conf.tun1.accept_local=1
# sudo sysctl -p

# sudo ip route flush cache
