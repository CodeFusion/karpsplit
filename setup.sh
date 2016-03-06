echo '1' > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port 8443
rm /root/sslsplit/connections.txt
touch /root/sslsplit/connections.txt
